"""dual_log_engine  -  a runnable, LightRAG-style dual-layer contextual memory engine.

The executable embodiment of the ``dual-log-memory`` doctrine:

  * episodic (LOW / operational) traces are captured and evicted (the *fix log*
    valence + the *sunset* rule),
  * distilled into semantic (HIGH / conceptual) graph structure (the *insight
    log* + *synthesis protocol* valence),
  * isolated per tenant/repo and retrieved by abstraction tier,
  * with every transaction recorded to a fail-silent audit ledger.

The default store is ``SqliteStore`` (indexed, incremental, on-disk). The
in-memory ``LightRAGGraphStore`` lives in the ``graph_store`` submodule and is
imported on demand, so ``import dual_log_engine`` does not pull in networkx  - 
keeping the capture hot path fast.
"""
from __future__ import annotations

from .audit import AuditWriter
from .clients import (
    AnthropicLLMClient,
    DistillResult,
    HeadroomLLMClient,
    LLMClient,
    MockLLMClient,
    TokenUsage,
)
from .engine import MemoryEngine, llm_from_env
from .envelope import (
    ENTITY_TYPES,
    RELATION_TYPES,
    Entity,
    EpisodicTrace,
    Level,
    MemoryEnvelope,
    Relation,
    wrap,
)
from .episodic import EpisodicLogStore
from .eviction_worker import LightRAGEvictionWorker
from .prompts import format_distillation_prompt
from .rag import CompiledContext, QueryMode, dual_level_rag_query
from .store import SqliteStore

__all__ = [
    "AuditWriter",
    "AnthropicLLMClient",
    "CompiledContext",
    "DistillResult",
    "ENTITY_TYPES",
    "Entity",
    "EpisodicLogStore",
    "EpisodicTrace",
    "HeadroomLLMClient",
    "LLMClient",
    "Level",
    "LightRAGEvictionWorker",
    "MemoryEngine",
    "MemoryEnvelope",
    "MockLLMClient",
    "QueryMode",
    "RELATION_TYPES",
    "Relation",
    "SqliteStore",
    "TokenUsage",
    "dual_level_rag_query",
    "format_distillation_prompt",
    "llm_from_env",
    "wrap",
]

__version__ = "0.2.0"
