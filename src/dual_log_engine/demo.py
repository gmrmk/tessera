"""End-to-end self-check: ingest -> evict -> distill -> graph -> query -> audit.

Run it: ``python -m dual_log_engine.demo``

Deterministic and network-free (the mock LLM is scripted), so the output is
stable run-to-run. Every assertion maps to a plan invariant:
  * incremental weight increment on a duplicate relation,
  * LOW -> HIGH tier elevation on re-ingest,
  * a HYBRID query returns both tiers,
  * a cross-tenant query returns zero leakage,
  * an audit JSON lands under ``.memory/traces/`` and nothing was swallowed.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from .audit import AuditWriter
from .clients import MockLLMClient
from .envelope import Entity, EpisodicTrace, Relation, wrap
from .episodic import EpisodicLogStore
from .eviction_worker import LightRAGEvictionWorker
from .graph_store import LightRAGGraphStore
from .rag import dual_level_rag_query


def _script(_batch: str) -> tuple[list[Entity], list[Relation]]:
    """A fixed dual-level extraction, returned fresh each call so repeated
    distillations exercise the incremental-merge path (weight += 1)."""
    entities = [
        Entity(entity_name="auth.py", entity_type="COMPONENT",
               description="token refresh path", level="LOW"),
        Entity(entity_name="error::timeout", entity_type="ERROR_TYPE",
               description="upstream timeout during refresh", level="LOW"),
        Entity(entity_name="principle::idempotency", entity_type="COMPONENT",
               description="make refresh idempotent under retry", level="HIGH"),
        Entity(entity_name="subsystem::auth", entity_type="COMPONENT",
               description="the auth subsystem at architectural altitude", level="HIGH"),
    ]
    relations = [
        Relation(source="auth.py", target="error::timeout", relation_type="CAUSES",
                 description="refresh storms cause upstream timeouts", weight=1, level="LOW"),
        Relation(source="principle::idempotency", target="subsystem::auth",
                 relation_type="DEPENDS_ON", description="the guideline governs auth", weight=1, level="HIGH"),
    ]
    return entities, relations


async def main(trace_dir: str | Path | None = None) -> None:
    if trace_dir is None:
        trace_dir = Path(tempfile.mkdtemp(prefix="dle-demo-")) / ".memory" / "traces"

    graph = LightRAGGraphStore()
    audit = AuditWriter(base_dir=trace_dir)
    worker = LightRAGEvictionWorker(MockLLMClient(script=_script), graph, audit)

    ts = 1_700_000_000.0
    now = ts + 100.0  # fixed clock just after the traces, so the 48h age window
    #                   never fires here and the count cap is the active policy.

    tasks: list[asyncio.Task] = []
    store = EpisodicLogStore(
        max_traces=2,
        now_fn=lambda: now,
        on_evict=lambda t, r, traces: tasks.append(worker.schedule(t, r, traces)),
    )
    # tenant "acme"/"api": 4 traces, cap 2 -> 2 evictions -> 2 distillations of (acme,api)
    for i in range(4):
        store.append(wrap("acme", "api", "run-1",
                          EpisodicTrace(trace_id=f"a{i}", agent_run_id="run-1", ts=ts + i,
                                        text=f"auth.py refresh attempt {i} failed: upstream timeout")))
    # tenant "globex"/"web": its own buffer, must stay isolated
    for i in range(3):
        store.append(wrap("globex", "web", "run-2",
                          EpisodicTrace(trace_id=f"b{i}", agent_run_id="run-2", ts=ts + i,
                                        text=f"worker.ts job {i} failed: exception")))

    await asyncio.gather(*tasks)

    # 1) incremental weight: CAUSES distilled twice for (acme,api) -> weight 2
    caused = graph.relation("acme", "api", "auth.py", "error::timeout", "CAUSES")
    assert caused is not None and caused["weight"] == 2, f"expected weight 2, got {caused}"

    # 2) HYBRID returns both tiers
    hybrid = await dual_level_rag_query(graph, "acme", "api", "why do refreshes fail?", "HYBRID")
    levels = {e["level"] for e in hybrid.entities}
    assert {"LOW", "HIGH"} <= levels, f"HYBRID missing a tier: {levels}"

    # 3) LOW / HIGH slices are disjoint by tier
    low = await dual_level_rag_query(graph, "acme", "api", "debug", "LOW")
    high = await dual_level_rag_query(graph, "acme", "api", "overview", "HIGH")
    assert all(e["level"] == "LOW" for e in low.entities) and low.entities
    assert all(e["level"] == "HIGH" for e in high.entities) and high.entities

    # 4) cross-tenant isolation: acme's view contains zero globex nodes (and vice versa)
    assert all(e["tenant_id"] == "acme" for e in hybrid.entities)
    globex = await dual_level_rag_query(graph, "globex", "web", "status", "HYBRID")
    assert globex.entities and all(e["tenant_id"] == "globex" for e in globex.entities)

    # 5) tier elevation on re-ingest (LOW then HIGH, description blended)
    graph.upsert_entity("acme", "api", Entity(entity_name="deploy.sh", entity_type="COMPONENT",
                                              description="first sighting", level="LOW"))
    graph.upsert_entity("acme", "api", Entity(entity_name="deploy.sh", entity_type="COMPONENT",
                                              description="recurring structural risk", level="HIGH"))
    elevated = graph.entity("acme", "api", "deploy.sh")
    assert elevated["level"] == "HIGH", f"expected HIGH, got {elevated}"
    assert "first sighting" in elevated["description"] and "structural risk" in elevated["description"]

    # 6) audit landed under .memory/traces and nothing was swallowed
    written = list(Path(trace_dir).rglob("*.json"))
    assert written, "no audit documents written"
    assert audit.errors == [], f"audit swallowed errors: {audit.errors}"

    print("dual_log_engine self-check")
    print(f"  graph: {graph.g.number_of_nodes()} nodes, {graph.g.number_of_edges()} edges")
    print(f"  CAUSES(auth.py -> error::timeout) weight = {caused['weight']}  (merged, not rebuilt)")
    print(f"  HYBRID tiers present: {sorted(levels)}")
    print(f"  isolation: acme={len(hybrid.entities)} entities, globex={len(globex.entities)} entities, no overlap")
    print(f"  elevation: deploy.sh LOW->HIGH, description blended")
    print(f"  audit: {len(written)} document(s) under {trace_dir}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
