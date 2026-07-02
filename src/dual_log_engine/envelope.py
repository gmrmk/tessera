"""Data contract  -  the multi-tenant metadata envelope and the typed records.

Every item that crosses the engine boundary  -  raw episodic traces, distilled
entities and relations, audit records  -  is wrapped in a ``MemoryEnvelope`` that
carries the three isolation keys (``tenant_id``, ``repo_id``, ``agent_run_id``)
alongside its ``payload``. Tenant isolation is then enforced *structurally*: the
graph keys every node by ``(tenant_id, repo_id, entity_name)`` and every query
filters on those keys at the store level (see
``graph_store.LightRAGGraphStore.query_subgraph``), so two tenants can use the
same ``entity_name`` without colliding and a query for one tenant can never
surface another's data.

These are ``TypedDict``s: structural, zero-runtime-cost contracts. They document
shape for static checkers but stay tolerant at runtime, because the distillation
LLM is an *untrusted* producer of entity/relation records  -  trust-but-verify
means the engine validates what comes back, it does not assume it is well typed.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

# Abstraction tier (the LightRAG dual level).
#   LOW  = granular / operational  -  components, error types, runtime variables,
#          immediate programmatic fixes (the "fix log" valence of the doctrine).
#   HIGH = conceptual  -  architectural principles, structural invariants,
#          recurring system behaviors (the "insight log" valence).
Level = Literal["LOW", "HIGH"]

# Known vocabularies. The spec lists these as examples ("e.g."), so ingestion is
# deliberately tolerant of unseen values  -  these constants document the expected
# set without constraining it at runtime.
ENTITY_TYPES: tuple[str, ...] = ("COMPONENT", "ERROR_TYPE", "DEVELOPER", "ENVIRONMENT")
RELATION_TYPES: tuple[str, ...] = ("MUTATES", "CAUSES", "RESOLVES", "DEPENDS_ON")


class Entity(TypedDict):
    """A node in the knowledge graph, tagged with its abstraction tier."""

    entity_name: str
    entity_type: str  # one of ENTITY_TYPES by convention; open at runtime
    description: str
    level: Level


class Relation(TypedDict):
    """A directed, typed, weighted edge between two entities."""

    source: str
    target: str
    relation_type: str  # one of RELATION_TYPES by convention; open at runtime
    description: str
    weight: int
    level: Level


class EpisodicTrace(TypedDict):
    """One raw execution trace held in the episodic buffer before distillation."""

    trace_id: str
    agent_run_id: str
    ts: float  # epoch seconds (UTC); the clock is injectable in EpisodicLogStore
    text: str  # the raw operational log text


class MemoryEnvelope(TypedDict):
    """Strict multi-tenant envelope wrapping every memory item.

    ``payload`` carries the actual context data  -  an ``EpisodicTrace``, an
    ``Entity``, a ``Relation``, or a free-form dict  -  isolated by the three ids.
    """

    tenant_id: str
    repo_id: str
    agent_run_id: str
    payload: dict[str, Any]


def wrap(tenant_id: str, repo_id: str, agent_run_id: str, payload: dict[str, Any]) -> MemoryEnvelope:
    """Convenience constructor for a well-formed envelope."""

    return MemoryEnvelope(
        tenant_id=tenant_id,
        repo_id=repo_id,
        agent_run_id=agent_run_id,
        payload=payload,
    )
