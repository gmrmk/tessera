"""dual_level_rag_query  -  LOW/HIGH/HYBRID modes, isolation, compiled context."""
from __future__ import annotations

import asyncio

import pytest

from dual_log_engine.envelope import Entity
from dual_log_engine.graph_store import LightRAGGraphStore
from dual_log_engine.rag import dual_level_rag_query


def _seed() -> LightRAGGraphStore:
    s = LightRAGGraphStore()
    s.upsert_entity("acme", "api", Entity(entity_name="auth.py", entity_type="COMPONENT", description="d", level="LOW"))
    s.upsert_entity("acme", "api", Entity(entity_name="principle", entity_type="COMPONENT", description="d", level="HIGH"))
    s.upsert_entity("globex", "web", Entity(entity_name="other", entity_type="COMPONENT", description="d", level="LOW"))
    return s


def test_low_mode_returns_only_low_tier():
    ctx = asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "q", "LOW"))
    assert {e["entity_name"] for e in ctx.entities} == {"auth.py"}


def test_high_mode_returns_only_high_tier():
    ctx = asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "q", "HIGH"))
    assert {e["entity_name"] for e in ctx.entities} == {"principle"}


def test_hybrid_mode_returns_both_tiers():
    ctx = asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "q", "HYBRID"))
    assert {e["level"] for e in ctx.entities} == {"LOW", "HIGH"}


def test_query_is_tenant_isolated():
    ctx = asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "q", "HYBRID"))
    assert all(e["tenant_id"] == "acme" for e in ctx.entities)
    assert "other" not in {e["entity_name"] for e in ctx.entities}


def test_compiled_context_renders_a_prompt_block():
    ctx = asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "why fail?", "HYBRID"))
    prompt = ctx.to_prompt()
    assert "Retrieved memory context" in prompt and "why fail?" in prompt
    assert ctx.token_estimate > 0


def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        asyncio.run(dual_level_rag_query(_seed(), "acme", "api", "q", "SIDEWAYS"))  # type: ignore[arg-type]
