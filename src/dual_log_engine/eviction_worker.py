"""LightRAGEvictionWorker  -  distils evicted raw traces into the graph, off-loop.

It marshals raw text per group, sends it through the distillation prompt to the
LLM client (mock or real), and ingests the returned entities/relations into
whatever store it was handed. It depends only on the store's ``upsert_entity`` /
``upsert_relation`` surface (a Protocol below), so it works with both
``LightRAGGraphStore`` (networkx) and ``SqliteStore``  -  and importing it pulls in
*neither* networkx nor SQLite, which keeps the capture hot path dependency-light.
"""
from __future__ import annotations

from typing import Optional, Protocol

from .audit import AuditWriter
from .clients import DistillResult, LLMClient
from .envelope import EpisodicTrace
from .prompts import format_distillation_prompt


class GraphLike(Protocol):
    """The minimal store surface the worker writes to."""

    def upsert_entity(self, tenant_id: str, repo_id: str, entity: dict) -> object: ...
    def upsert_relation(self, tenant_id: str, repo_id: str, relation: dict) -> None: ...


class LightRAGEvictionWorker:
    def __init__(
        self,
        llm: LLMClient,
        graph: GraphLike,
        audit: Optional[AuditWriter] = None,
    ) -> None:
        self.llm = llm
        self.graph = graph
        self.audit = audit

    @staticmethod
    def _batch_text(traces: list[EpisodicTrace]) -> str:
        return "\n".join(t["text"] for t in traces)

    async def distill(
        self, tenant_id: str, repo_id: str, traces: list[EpisodicTrace]
    ) -> DistillResult:
        """Distil one tenant/repo group of evicted traces into graph structure."""
        agent_run_id = traces[-1]["agent_run_id"] if traces else "unknown"
        prompt = format_distillation_prompt(self._batch_text(traces))

        result = await self.llm.distill(prompt)

        # trust-but-verify: the LLM output is untrusted; the graph upserts validate
        # shape and the audit record preserves the exact prompt + output for the
        # human (eyes-on) verifier.
        for entity in result.entities:
            self.graph.upsert_entity(tenant_id, repo_id, entity)
        for relation in result.relations:
            self.graph.upsert_relation(tenant_id, repo_id, relation)

        if self.audit is not None:
            await self.audit.write(
                tenant_id=tenant_id,
                repo_id=repo_id,
                agent_run_id=agent_run_id,
                prompt=prompt,
                context_snippets={"entities": result.entities, "relations": result.relations},
                usage=result.usage,
            )
        return result

    def schedule(
        self, tenant_id: str, repo_id: str, traces: list[EpisodicTrace]
    ) -> "object":
        """Fire-and-forget: schedule distillation on the loop and return at once.

        Kept for the in-memory / live-loop path; the SQLite engine drives
        distillation from the background daemon instead.
        """
        import asyncio

        return asyncio.create_task(self.distill(tenant_id, repo_id, list(traces)))
