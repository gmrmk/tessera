"""MemoryEngine (SQLite)  -  fast capture, background distil, cache, persistence."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from dual_log_engine.clients import AnthropicLLMClient, HeadroomLLMClient, MockLLMClient
from dual_log_engine.engine import MemoryEngine, llm_from_env


def _root() -> Path:
    return Path(tempfile.mkdtemp(prefix="dle-engine-")) / ".memory"


def test_capture_is_a_fast_insert_without_distillation():
    e = MemoryEngine(root=_root(), max_traces=2)
    out = e.capture("acme", "api", "run", "Parser.py failed: timeout error")
    assert out["buffered"] == 1
    assert e.stats()["nodes"] == 0  # capture does not distil


def test_distill_due_promotes_overdue_traces_and_keeps_the_buffer():
    e = MemoryEngine(root=_root(), max_traces=2)
    for line in ("Parser.py failed: timeout error", "Loader.py crashed: exception", "a third line"):
        e.capture("acme", "api", "run", line)
    res = asyncio.run(e.distill_due("acme", "api"))
    assert res["distilled"] > 0
    assert e.stats()["nodes"] > 0
    assert e.store.buffer_count("acme", "api") == 2  # newest 2 retained


def test_flush_distils_the_whole_buffer_and_refreshes_cache():
    e = MemoryEngine(root=_root(), max_traces=100)  # nothing evicts on its own
    e.capture("acme", "api", "run", "Parser.py failed: timeout error")
    assert e.stats()["nodes"] == 0  # buffered, not distilled
    res = asyncio.run(e.flush("acme", "api"))
    assert res["flushed"] == 1 and res["distilled"] > 0
    assert e.stats()["nodes"] > 0
    assert e.store.buffer_count("acme", "api") == 0
    # the daemon-style cache was refreshed during flush
    cached = e.cached_context("acme", "api", "HIGH")
    assert cached and "\n- " in cached


def test_query_after_distill_returns_both_tiers():
    e = MemoryEngine(root=_root(), max_traces=100)
    e.capture("acme", "api", "run", "Parser.py failed: timeout error")
    asyncio.run(e.flush("acme", "api"))
    ctx = asyncio.run(e.query("acme", "api", "why fail", "HYBRID"))
    assert {x["level"] for x in ctx.entities} == {"LOW", "HIGH"}


def test_state_and_buffer_persist_to_a_fresh_engine():
    root = _root()
    e1 = MemoryEngine(root=root, max_traces=100)
    e1.capture("acme", "api", "run", "Parser.py failed: timeout error")  # buffered only
    asyncio.run(e1.flush("acme", "api"))                                  # -> graph
    e1.capture("acme", "api", "run", "Loader.py crashed: exception")     # buffered only
    nodes = e1.stats()["nodes"]

    e2 = MemoryEngine(root=root, max_traces=100)  # a fresh process re-opens the same db
    assert e2.stats()["nodes"] == nodes               # distilled graph persisted
    assert e2.store.buffer_count("acme", "api") == 1  # buffered trace persisted


def test_cross_tenant_isolation_in_the_engine():
    e = MemoryEngine(root=_root(), max_traces=100)
    e.capture("acme", "api", "run", "Parser.py failed: timeout error")
    e.capture("globex", "web", "run", "Loader.py crashed: exception")
    asyncio.run(e.flush("acme", "api"))
    asyncio.run(e.flush("globex", "web"))
    acme = asyncio.run(e.query("acme", "api", "q", "HYBRID"))
    assert acme.entities and all(x["tenant_id"] == "acme" for x in acme.entities)


def test_llm_from_env_selects_backend(monkeypatch):
    monkeypatch.delenv("DLE_LLM", raising=False)
    monkeypatch.delenv("DLE_HEADROOM", raising=False)
    assert isinstance(llm_from_env(), MockLLMClient)

    monkeypatch.setenv("DLE_LLM", "anthropic")
    assert isinstance(llm_from_env(), AnthropicLLMClient)  # constructs without anthropic installed

    monkeypatch.setenv("DLE_HEADROOM", "1")
    assert isinstance(llm_from_env(), HeadroomLLMClient)  # wraps the inner client
