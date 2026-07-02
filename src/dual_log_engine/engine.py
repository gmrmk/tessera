"""MemoryEngine  -  the fast, SQLite-backed facade.

Built for a long, hot session. Two ideas keep it efficient:

  * **The hot path is one indexed write.** ``capture`` is a single
    ``INSERT`` into the episodic table  -  no graph load, no full rewrite, no LLM.
    Heavy work (distillation) is deliberately *not* on this path.
  * **Distillation runs off the hot path.** The background daemon (``dle-serve``)
    calls ``distill_due`` on a poll; it pulls episodic traces past the eviction
    threshold, distils them into the graph, deletes the raw rows, and refreshes a
    rendered-context cache. Injection then reads that cache (``cached_context``)
    instead of traversing the graph.

Everything persists in one SQLite file under ``root`` (``memory.db``, WAL mode),
shared by the hooks, the MCP server, and the daemon. Backend selection is
environment-driven (``DLE_LLM=anthropic`` -> Opus 4.8, ``DLE_HEADROOM=1`` ->
compress first); default is the deterministic in-process mock.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from .audit import AuditWriter
from .clients import AnthropicLLMClient, HeadroomLLMClient, LLMClient, MockLLMClient
from .envelope import EpisodicTrace
from .episodic import DEFAULT_MAX_AGE_SECONDS, DEFAULT_MAX_TRACES
from .eviction_worker import LightRAGEvictionWorker
from .rag import CompiledContext, QueryMode, dual_level_rag_query
from .store import SqliteStore

# Tiers the daemon pre-renders for fast injection, with a natural query label each.
_CACHE_QUERY = {"HIGH": "durable guidelines and recurring risks", "HYBRID": "relevant prior context"}
_CACHED_MODES = tuple(_CACHE_QUERY)


def llm_from_env() -> LLMClient:
    """Pick the distillation backend from environment variables (default: mock)."""
    backend = os.environ.get("DLE_LLM", "mock").lower()
    client: LLMClient = AnthropicLLMClient() if backend == "anthropic" else MockLLMClient()
    if os.environ.get("DLE_HEADROOM", "").lower() in ("1", "true", "yes"):
        client = HeadroomLLMClient(client)  # compress the batch before the model sees it
    return client


class MemoryEngine:
    def __init__(
        self,
        root: str | Path = ".memory",
        llm: Optional[LLMClient] = None,
        max_traces: int = DEFAULT_MAX_TRACES,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        self.root = Path(root)
        self.max_traces = max_traces
        self.max_age_seconds = max_age_seconds

        self.store = SqliteStore(self.root / "memory.db")
        self.llm: LLMClient = llm or llm_from_env()
        self.audit = AuditWriter(base_dir=self.root / "traces")
        # The worker upserts into whatever store it is given; SqliteStore duck-types
        # as the graph store (same upsert_entity / upsert_relation surface).
        self.worker = LightRAGEvictionWorker(self.llm, self.store, self.audit)

    def close(self) -> None:
        self.store.close()

    # --- hot path: capture (one indexed insert, no LLM) --------------------- #

    def capture(
        self, tenant_id: str, repo_id: str, agent_run_id: str, text: str,
        trace_id: Optional[str] = None,
    ) -> dict:
        """Record one raw trace. O(1) indexed insert; distillation happens later."""
        self.store.add_trace(
            tenant_id, repo_id, agent_run_id,
            trace_id or f"{agent_run_id}-{time.time_ns()}", time.time(), text)
        return {"buffered": self.store.buffer_count(tenant_id, repo_id)}

    # --- background: distillation + cache refresh --------------------------- #

    async def _distill(self, tenant_id: str, repo_id: str, traces: list[dict]) -> int:
        if not traces:
            return 0
        episodic = [
            EpisodicTrace(trace_id=t["trace_id"], agent_run_id=t["agent_run_id"],
                          ts=t["ts"], text=t["text"])
            for t in traces
        ]
        result = await self.worker.distill(tenant_id, repo_id, episodic)
        self.store.delete_traces([t["id"] for t in traces])
        await self.refresh_cache(tenant_id, repo_id)
        return len(result.entities) + len(result.relations)

    async def distill_due(self, tenant_id: Optional[str] = None, repo_id: Optional[str] = None) -> dict:
        """Distil every group's *overdue* traces (the daemon's per-tick job)."""
        groups = (
            [(tenant_id, repo_id)] if tenant_id and repo_id
            else self.store.groups_with_traces()
        )
        distilled = touched = 0
        for t, r in groups:
            due = self.store.due_traces(t, r, self.max_traces, self.max_age_seconds)
            if due:
                distilled += await self._distill(t, r, due)
                touched += 1
        return {"groups": touched, "distilled": distilled}

    async def flush(self, tenant_id: str, repo_id: str) -> dict:
        """Distil a group's *entire* current buffer now (session-end fallback)."""
        traces = self.store.group_traces(tenant_id, repo_id)
        distilled = await self._distill(tenant_id, repo_id, traces)
        return {"flushed": len(traces), "distilled": distilled}

    async def refresh_cache(self, tenant_id: str, repo_id: str) -> None:
        """Pre-render the tiers injection hooks read, so injection is a cache hit."""
        for mode in _CACHED_MODES:
            ctx = await dual_level_rag_query(self.store, tenant_id, repo_id, _CACHE_QUERY[mode], mode)  # type: ignore[arg-type]
            self.store.set_cache(tenant_id, repo_id, mode, ctx.to_prompt())

    # --- read path ---------------------------------------------------------- #

    async def query(
        self, tenant_id: str, repo_id: str, query: str, mode: QueryMode = "HYBRID"
    ) -> CompiledContext:
        return await dual_level_rag_query(self.store, tenant_id, repo_id, query, mode)

    def cached_context(self, tenant_id: str, repo_id: str, mode: str = "HIGH") -> Optional[str]:
        """The pre-rendered context for a tier  -  a single SELECT, no traversal."""
        return self.store.get_cache(tenant_id, repo_id, mode)

    def stats(self, tenant_id: Optional[str] = None, repo_id: Optional[str] = None) -> dict:
        out: dict = {**self.store.counts(), "root": str(self.root)}
        if tenant_id and repo_id:
            out["scoped"] = {
                "tenant_id": tenant_id, "repo_id": repo_id,
                **self.store.scoped_counts(tenant_id, repo_id),
            }
        return out
