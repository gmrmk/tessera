"""LightRAGGraphStore  -  incremental, dual-level, multi-tenant graph memory.

Backed by a single ``networkx.MultiDiGraph``. Three design choices are
load-bearing and were verified against the networkx docs/runtime this session:

  * **MultiDiGraph, not Graph/DiGraph.** Relation identity is
    ``(source, target, relation_type)``  -  two entities can have several distinct
    typed edges (a CAUSES *and* a RESOLVES). A plain graph keeps one edge per
    pair and would collapse them; a multigraph keyed by ``relation_type`` keeps
    them separate, which is exactly the per-type weight counter the spec wants.

  * **subgraph_view for retrieval, never a rebuild.** ``query_subgraph`` returns
    ``networkx.subgraph_view(...)``  -  a *lazy view* over the live graph, not a
    copy. That satisfies both "incremental, no destructive reconstruction" and
    "database-level predicate filter, not local post-retrieval filtering".

  * **String node ids, not tuples.** Nodes are keyed by the NUL-delimited string
    ``"{tenant_id}\\x00{repo_id}\\x00{entity_name}"`` so the graph round-trips
    cleanly through JSON for the on-disk persistence the MCP server and hooks
    share (a tuple id would deserialize to an unhashable list). NUL never appears
    in log text, so it is a safe separator and tenant isolation stays structural.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import networkx as nx

from .envelope import Entity, Level, Relation

_SEP = "\x00"
NodeId = str  # "{tenant_id}\x00{repo_id}\x00{entity_name}"


def _blend(existing: str, incoming: str) -> str:
    """Enrich a description rather than overwrite it (append unseen detail)."""
    existing = (existing or "").strip()
    incoming = (incoming or "").strip()
    if not incoming or incoming in existing:
        return existing
    if not existing:
        return incoming
    return f"{existing} | {incoming}"


def _elevate(existing: Level, incoming: Level) -> Level:
    """Tier is monotonic upward: once HIGH, stays HIGH."""
    return "HIGH" if existing == "HIGH" or incoming == "HIGH" else "LOW"


class LightRAGGraphStore:
    def __init__(self) -> None:
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()

    @staticmethod
    def _nid(tenant_id: str, repo_id: str, name: str) -> NodeId:
        return f"{tenant_id}{_SEP}{repo_id}{_SEP}{name}"

    # --- ingestion (incremental merge, never rebuild) ----------------------- #

    def upsert_entity(self, tenant_id: str, repo_id: str, entity: Entity) -> NodeId:
        """Insert a node, or merge into the existing one (blend desc, elevate tier)."""
        nid = self._nid(tenant_id, repo_id, entity["entity_name"])
        if self.g.has_node(nid):
            data = self.g.nodes[nid]
            data["description"] = _blend(data.get("description", ""), entity["description"])
            data["level"] = _elevate(data.get("level", "LOW"), entity["level"])
            # keep the first non-empty entity_type; enrich only if we had none
            if not data.get("entity_type") and entity.get("entity_type"):
                data["entity_type"] = entity["entity_type"]
        else:
            self.g.add_node(
                nid,
                tenant_id=tenant_id,
                repo_id=repo_id,
                entity_name=entity["entity_name"],
                entity_type=entity["entity_type"],
                description=entity["description"],
                level=entity["level"],
            )
        return nid

    def upsert_relation(self, tenant_id: str, repo_id: str, relation: Relation) -> None:
        """Insert a typed edge, or increment its weight (+1) and blend its description."""
        u = self._nid(tenant_id, repo_id, relation["source"])
        v = self._nid(tenant_id, repo_id, relation["target"])
        # Ensure endpoints exist so an edge never dangles. Minimal placeholder
        # nodes inherit the relation's tier and are enriched if a real entity
        # for the same name is upserted later.
        for end, name in ((u, relation["source"]), (v, relation["target"])):
            if not self.g.has_node(end):
                self.g.add_node(end, tenant_id=tenant_id, repo_id=repo_id, entity_name=name,
                                entity_type="", description="", level=relation["level"])

        rt = relation["relation_type"]
        if self.g.has_edge(u, v, key=rt):
            data = self.g[u][v][rt]
            data["weight"] = int(data.get("weight", 1)) + 1
            data["description"] = _blend(data.get("description", ""), relation["description"])
            data["level"] = _elevate(data.get("level", "LOW"), relation["level"])
        else:
            self.g.add_edge(
                u, v, key=rt,
                relation_type=rt,
                tenant_id=tenant_id,
                repo_id=repo_id,
                description=relation["description"],
                weight=int(relation.get("weight", 1)) or 1,
                level=relation["level"],
            )

    # --- retrieval (pre-filtered lazy view) --------------------------------- #

    def query_subgraph(
        self, tenant_id: str, repo_id: str, level: Optional[Level] = None
    ) -> nx.MultiDiGraph:
        """Return a lazy, pre-filtered view: only this tenant/repo (and level, if given).

        Filtering happens at the store level via predicates passed to
        ``subgraph_view``  -  the full graph is never materialised-then-trimmed.
        ``level=None`` is the HYBRID slice (both tiers).
        """

        def keep_node(n: NodeId) -> bool:
            d = self.g.nodes[n]
            if d.get("tenant_id") != tenant_id or d.get("repo_id") != repo_id:
                return False
            return level is None or d.get("level") == level

        def keep_edge(u: NodeId, v: NodeId, k: str) -> bool:
            d = self.g.edges[u, v, k]
            if d.get("tenant_id") != tenant_id or d.get("repo_id") != repo_id:
                return False
            return level is None or d.get("level") == level

        return nx.subgraph_view(self.g, filter_node=keep_node, filter_edge=keep_edge)

    def fetch(
        self, tenant_id: str, repo_id: str, level: Optional[Level] = None
    ) -> tuple[list[dict], list[dict]]:
        """Return (entities, relations) dicts for a scope/tier  -  the shared store
        interface the RAG layer consumes (same shape as SqliteStore.fetch)."""
        view = self.query_subgraph(tenant_id, repo_id, level)
        entities = [dict(view.nodes[n]) for n in view.nodes]
        relations: list[dict] = []
        for u, v, _key, data in view.edges(keys=True, data=True):
            relations.append({
                "source": view.nodes[u].get("entity_name", u),
                "target": view.nodes[v].get("entity_name", v),
                **data,
            })
        return entities, relations

    # --- persistence (shared on-disk substrate for the MCP server + hooks) --- #

    def save_json(self, path: str | Path) -> None:
        """Serialise the whole graph to JSON (node-link format, string ids)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(nx.node_link_data(self.g, edges="edges")), encoding="utf-8")

    def load_json(self, path: str | Path) -> None:
        """Replace the in-memory graph from a JSON file (no-op if it is missing)."""
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        self.g = nx.node_link_graph(data, edges="edges", multigraph=True, directed=True)

    # --- small conveniences ------------------------------------------------- #

    def entity(self, tenant_id: str, repo_id: str, name: str) -> Optional[dict]:
        nid = self._nid(tenant_id, repo_id, name)
        return dict(self.g.nodes[nid]) if self.g.has_node(nid) else None

    def relation(self, tenant_id: str, repo_id: str, source: str, target: str, relation_type: str) -> Optional[dict]:
        u = self._nid(tenant_id, repo_id, source)
        v = self._nid(tenant_id, repo_id, target)
        if self.g.has_edge(u, v, key=relation_type):
            return dict(self.g[u][v][relation_type])
        return None
