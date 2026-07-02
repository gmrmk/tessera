"""envelope  -  the multi-tenant wrapper contract."""
from __future__ import annotations

from dual_log_engine.envelope import EpisodicTrace, wrap


def test_wrap_builds_a_well_formed_envelope():
    trace = EpisodicTrace(trace_id="t1", agent_run_id="run-1", ts=1000.0, text="log")
    env = wrap("acme", "api", "run-1", trace)
    assert env["tenant_id"] == "acme"
    assert env["repo_id"] == "api"
    assert env["agent_run_id"] == "run-1"
    assert env["payload"] is trace


def test_envelope_payload_is_open_to_any_record_kind():
    env = wrap("t", "r", "run", {"arbitrary": "context"})
    assert env["payload"]["arbitrary"] == "context"
