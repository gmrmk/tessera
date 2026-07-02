"""SqliteStore  -  the fast, incremental, indexed backing store.

Replaces the load-everything / rewrite-everything networkx+JSON path with an
embedded SQLite database. Three properties make it "hyper-efficient":

  * **Incremental upserts.** Each entity/relation is one ``INSERT ... ON CONFLICT
    DO UPDATE``  -  the merge (weight +1, blend description, elevate LOW->HIGH) runs
    atomically in SQL, no read-modify-write, no full-graph rewrite. O(1) per write.
  * **Indexed predicate queries.** ``fetch`` is ``WHERE tenant_id=? AND repo_id=?
    [AND level=?]`` over indexes on ``(tenant_id, repo_id, level)``  -  O(matching
    rows), not O(all tenants). This *is* the spec's "database-level pre-filter".
  * **Shared across processes.** The hooks, the MCP server, and the daemon all
    open the same ``.db`` file. WAL mode + ``busy_timeout`` handle concurrency, so
    SQLite is also the IPC  -  no socket protocol needed.

It implements the same informal store interface the eviction worker and the RAG
layer use (``upsert_entity``, ``upsert_relation``, ``fetch``, ``entity``,
``relation``), so it is a drop-in alternative to ``LightRAGGraphStore``.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional

from .envelope import Entity, Level, Relation

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    tenant_id   TEXT NOT NULL,
    repo_id     TEXT NOT NULL,
    entity_name TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    level       TEXT NOT NULL DEFAULT 'LOW',
    PRIMARY KEY (tenant_id, repo_id, entity_name)
);
CREATE INDEX IF NOT EXISTS idx_nodes_scope ON nodes(tenant_id, repo_id, level);

CREATE TABLE IF NOT EXISTS edges (
    tenant_id     TEXT NOT NULL,
    repo_id       TEXT NOT NULL,
    source        TEXT NOT NULL,
    target        TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    weight        INTEGER NOT NULL DEFAULT 1,
    level         TEXT NOT NULL DEFAULT 'LOW',
    PRIMARY KEY (tenant_id, repo_id, source, target, relation_type)
);
CREATE INDEX IF NOT EXISTS idx_edges_scope ON edges(tenant_id, repo_id, level);

CREATE TABLE IF NOT EXISTS episodic (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL,
    repo_id      TEXT NOT NULL,
    agent_run_id TEXT NOT NULL,
    trace_id     TEXT NOT NULL,
    ts           REAL NOT NULL,
    text         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_episodic_scope ON episodic(tenant_id, repo_id, ts);

CREATE TABLE IF NOT EXISTS cache (
    tenant_id TEXT NOT NULL,
    repo_id   TEXT NOT NULL,
    mode      TEXT NOT NULL,
    payload   TEXT NOT NULL,
    updated   REAL NOT NULL,
    PRIMARY KEY (tenant_id, repo_id, mode)
);
"""

# The whole node merge in one atomic statement: blend description (skip if the
# incoming text is already contained), keep the first non-empty type, elevate to
# HIGH if either side is HIGH.
_UPSERT_NODE = """
INSERT INTO nodes(tenant_id, repo_id, entity_name, entity_type, description, level)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, repo_id, entity_name) DO UPDATE SET
    description = CASE
        WHEN excluded.description = '' THEN description
        WHEN instr(description, excluded.description) > 0 THEN description
        WHEN description = '' THEN excluded.description
        ELSE description || ' | ' || excluded.description END,
    entity_type = CASE WHEN entity_type != '' THEN entity_type ELSE excluded.entity_type END,
    level = CASE WHEN level = 'HIGH' OR excluded.level = 'HIGH' THEN 'HIGH' ELSE 'LOW' END
"""

# Same blend/elevate for edges, plus the +1 weight increment on a duplicate.
_UPSERT_EDGE = """
INSERT INTO edges(tenant_id, repo_id, source, target, relation_type, description, weight, level)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, repo_id, source, target, relation_type) DO UPDATE SET
    weight = weight + 1,
    description = CASE
        WHEN excluded.description = '' THEN description
        WHEN instr(description, excluded.description) > 0 THEN description
        WHEN description = '' THEN excluded.description
        ELSE description || ' | ' || excluded.description END,
    level = CASE WHEN level = 'HIGH' OR excluded.level = 'HIGH' THEN 'HIGH' ELSE 'LOW' END
"""


class SqliteStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- ingestion (atomic incremental merge) ------------------------------- #

    def upsert_entity(self, tenant_id: str, repo_id: str, entity: Entity) -> None:
        self.conn.execute(_UPSERT_NODE, (
            tenant_id, repo_id, entity["entity_name"],
            entity.get("entity_type", ""), entity["description"], entity["level"],
        ))
        self.conn.commit()

    def upsert_relation(self, tenant_id: str, repo_id: str, relation: Relation) -> None:
        self.conn.execute(_UPSERT_EDGE, (
            tenant_id, repo_id, relation["source"], relation["target"],
            relation["relation_type"], relation["description"],
            int(relation.get("weight", 1)) or 1, relation["level"],
        ))
        self.conn.commit()

    # --- retrieval (indexed predicate filter) ------------------------------- #

    def fetch(
        self, tenant_id: str, repo_id: str, level: Optional[Level] = None
    ) -> tuple[list[dict], list[dict]]:
        """Return (entities, relations) for a tenant/repo, optionally one tier.

        Filtering is pushed into SQL over the ``(tenant_id, repo_id, level)``
        indexes  -  the DB returns only matching rows.
        """
        if level is None:
            nrows = self.conn.execute(
                "SELECT * FROM nodes WHERE tenant_id=? AND repo_id=?", (tenant_id, repo_id))
            erows = self.conn.execute(
                "SELECT * FROM edges WHERE tenant_id=? AND repo_id=?", (tenant_id, repo_id))
        else:
            nrows = self.conn.execute(
                "SELECT * FROM nodes WHERE tenant_id=? AND repo_id=? AND level=?",
                (tenant_id, repo_id, level))
            erows = self.conn.execute(
                "SELECT * FROM edges WHERE tenant_id=? AND repo_id=? AND level=?",
                (tenant_id, repo_id, level))
        return [dict(r) for r in nrows], [dict(r) for r in erows]

    def entity(self, tenant_id: str, repo_id: str, name: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM nodes WHERE tenant_id=? AND repo_id=? AND entity_name=?",
            (tenant_id, repo_id, name)).fetchone()
        return dict(row) if row else None

    def relation(self, tenant_id: str, repo_id: str, source: str, target: str, relation_type: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM edges WHERE tenant_id=? AND repo_id=? AND source=? AND target=? AND relation_type=?",
            (tenant_id, repo_id, source, target, relation_type)).fetchone()
        return dict(row) if row else None

    # --- episodic buffer (raw traces) --------------------------------------- #

    def add_trace(self, tenant_id, repo_id, agent_run_id, trace_id, ts, text) -> None:
        self.conn.execute(
            "INSERT INTO episodic(tenant_id, repo_id, agent_run_id, trace_id, ts, text) VALUES (?,?,?,?,?,?)",
            (tenant_id, repo_id, agent_run_id, trace_id, ts, text))
        self.conn.commit()

    def buffer_count(self, tenant_id: str, repo_id: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM episodic WHERE tenant_id=? AND repo_id=?",
            (tenant_id, repo_id)).fetchone()[0]

    def group_traces(self, tenant_id: str, repo_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM episodic WHERE tenant_id=? AND repo_id=? ORDER BY ts ASC, id ASC",
            (tenant_id, repo_id))
        return [dict(r) for r in rows]

    def due_traces(
        self, tenant_id: str, repo_id: str, max_traces: int, max_age_seconds: float,
        now: Optional[float] = None,
    ) -> list[dict]:
        """Traces past the eviction threshold: older than the window OR beyond the
        most-recent ``max_traces``."""
        now = time.time() if now is None else now
        cutoff = now - max_age_seconds
        rows = self.group_traces(tenant_id, repo_id)
        keep_recent_ids = {r["id"] for r in rows[-max_traces:]} if max_traces > 0 else set()
        return [r for r in rows if r["ts"] < cutoff or r["id"] not in keep_recent_ids]

    def delete_traces(self, ids: list[int]) -> None:
        if not ids:
            return
        self.conn.executemany("DELETE FROM episodic WHERE id=?", [(i,) for i in ids])
        self.conn.commit()

    def groups_with_traces(self) -> list[tuple[str, str]]:
        rows = self.conn.execute("SELECT DISTINCT tenant_id, repo_id FROM episodic")
        return [(r["tenant_id"], r["repo_id"]) for r in rows]

    # --- injection cache ---------------------------------------------------- #

    def set_cache(self, tenant_id: str, repo_id: str, mode: str, payload: str) -> None:
        self.conn.execute(
            "INSERT INTO cache(tenant_id, repo_id, mode, payload, updated) VALUES (?,?,?,?,?) "
            "ON CONFLICT(tenant_id, repo_id, mode) DO UPDATE SET payload=excluded.payload, updated=excluded.updated",
            (tenant_id, repo_id, mode, payload, time.time()))
        self.conn.commit()

    def get_cache(self, tenant_id: str, repo_id: str, mode: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT payload FROM cache WHERE tenant_id=? AND repo_id=? AND mode=?",
            (tenant_id, repo_id, mode)).fetchone()
        return row["payload"] if row else None

    # --- stats -------------------------------------------------------------- #

    def counts(self) -> dict:
        n = self.conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        e = self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        return {"nodes": n, "edges": e}

    def scoped_counts(self, tenant_id: str, repo_id: str) -> dict:
        n = self.conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE tenant_id=? AND repo_id=?", (tenant_id, repo_id)).fetchone()[0]
        e = self.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE tenant_id=? AND repo_id=?", (tenant_id, repo_id)).fetchone()[0]
        return {"nodes": n, "edges": e, "buffered_traces": self.buffer_count(tenant_id, repo_id)}
