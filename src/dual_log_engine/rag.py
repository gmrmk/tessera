"""Dual-level RAG core  -  LOW / HIGH / HYBRID retrieval over a store.

``dual_level_rag_query`` is the read side. It selects a pre-filtered slice by
abstraction tier and compiles it into a unified context structure ready to inject
into a final-generation prompt:

  * **LOW**     -  narrow, pinpoint debugging: granular components and errors.
  * **HIGH**    -  systemic overview / health: architectural principles.
  * **HYBRID**  -  both tiers stitched together.

It depends only on ``store.fetch(tenant_id, repo_id, level)``  -  satisfied by both
``LightRAGGraphStore`` (in-memory) and ``SqliteStore`` (indexed, on-disk)  -  so the
retrieval backend is swappable. The function is ``async`` because this is the
seam where a real semantic-retrieval (embedding) step would slot in later.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional, Protocol

from .clients import estimate_tokens

QueryMode = Literal["LOW", "HIGH", "HYBRID"]
_MODE_TO_LEVEL: dict[QueryMode, Any] = {"LOW": "LOW", "HIGH": "HIGH", "HYBRID": None}


class SupportsFetch(Protocol):
    def fetch(
        self, tenant_id: str, repo_id: str, level: Optional[str] = None
    ) -> tuple[list[dict], list[dict]]: ...


@dataclass
class CompiledContext:
    """The compiled retrieval result, ready for final-generation injection."""

    mode: QueryMode
    query: str
    tenant_id: str
    repo_id: str
    entities: list[dict]
    relations: list[dict]

    def to_prompt(self) -> str:
        """Render the slice into a unified context block."""
        lines = [
            f"# Retrieved memory context (mode={self.mode}) for query: {self.query!r}",
            "",
            "## Entities",
        ]
        for e in self.entities:
            lines.append(f"- [{e.get('level')}] {e.get('entity_name')} ({e.get('entity_type')}): {e.get('description')}")
        lines.append("")
        lines.append("## Relations")
        for r in self.relations:
            lines.append(
                f"- [{r.get('level')}] ({r.get('weight')}x) {r.get('source')} "
                f"-{r.get('relation_type')}-> {r.get('target')}: {r.get('description')}"
            )
        return "\n".join(lines)

    @property
    def token_estimate(self) -> int:
        return estimate_tokens(self.to_prompt())


async def dual_level_rag_query(
    store: SupportsFetch,
    tenant_id: str,
    repo_id: str,
    query: str,
    mode: QueryMode = "HYBRID",
) -> CompiledContext:
    """Compile a tenant/repo slice at the requested abstraction tier."""
    if mode not in _MODE_TO_LEVEL:
        raise ValueError(f"unknown mode {mode!r}; expected LOW, HIGH, or HYBRID")
    entities, relations = store.fetch(tenant_id, repo_id, _MODE_TO_LEVEL[mode])
    return CompiledContext(
        mode=mode,
        query=query,
        tenant_id=tenant_id,
        repo_id=repo_id,
        entities=entities,
        relations=relations,
    )
