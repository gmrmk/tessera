"""LightRAGEvictionWorker  -  distill into the graph, audit, and stay non-blocking."""
from __future__ import annotations

import asyncio

from dual_log_engine.audit import AuditWriter
from dual_log_engine.clients import DistillResult, MockLLMClient, TokenUsage
from dual_log_engine.envelope import Entity, EpisodicTrace, Relation
from dual_log_engine.eviction_worker import LightRAGEvictionWorker
from dual_log_engine.graph_store import LightRAGGraphStore


def _trace(i, run="run-1", ts=0.0, text="auth.py failed: timeout error"):
    return EpisodicTrace(trace_id=f"t{i}", agent_run_id=run, ts=ts, text=text)


def _script(_batch):
    return (
        [Entity(entity_name="auth.py", entity_type="COMPONENT", description="d", level="LOW"),
         Entity(entity_name="principle::x", entity_type="COMPONENT", description="d", level="HIGH")],
        [Relation(source="auth.py", target="principle::x", relation_type="CAUSES",
                  description="d", weight=1, level="LOW")],
    )


def test_distill_ingests_entities_and_relations_into_graph():
    graph = LightRAGGraphStore()
    worker = LightRAGEvictionWorker(MockLLMClient(script=_script), graph)
    result = asyncio.run(worker.distill("acme", "api", [_trace(0), _trace(1)]))
    assert isinstance(result, DistillResult)
    assert graph.entity("acme", "api", "auth.py") is not None
    assert graph.relation("acme", "api", "auth.py", "principle::x", "CAUSES")["weight"] == 1


def test_distill_writes_an_audit_record():
    graph = LightRAGGraphStore()
    audit = AuditWriter(base_dir=_tmp())
    worker = LightRAGEvictionWorker(MockLLMClient(script=_script), graph, audit)
    asyncio.run(worker.distill("acme", "api", [_trace(0)]))
    assert audit._seq == 1 and audit.errors == []


def test_schedule_is_non_blocking():
    asyncio.run(_non_blocking_body())


async def _non_blocking_body():
    graph = LightRAGGraphStore()
    gate = asyncio.Event()

    class SlowLLM:
        async def distill(self, prompt):
            await gate.wait()  # block until released
            return DistillResult(
                entities=[Entity(entity_name="late", entity_type="COMPONENT", description="d", level="LOW")],
                relations=[], usage=TokenUsage())

    worker = LightRAGEvictionWorker(SlowLLM(), graph)
    task = worker.schedule("acme", "api", [_trace(0)])

    # control returned to us immediately: the task has not finished, graph untouched
    assert not task.done()
    assert graph.entity("acme", "api", "late") is None

    gate.set()
    await task
    assert task.done()
    assert graph.entity("acme", "api", "late") is not None


def _tmp():
    import tempfile
    from pathlib import Path
    return Path(tempfile.mkdtemp(prefix="dle-evict-")) / ".memory" / "traces"
