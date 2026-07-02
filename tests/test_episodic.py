"""EpisodicLogStore  -  count cap, 48h window, per-group isolation, evict callback."""
from __future__ import annotations

from dual_log_engine.envelope import EpisodicTrace, wrap
from dual_log_engine.episodic import EpisodicLogStore


def _env(tenant, repo, run, trace_id, ts, text="log line"):
    return wrap(tenant, repo, run, EpisodicTrace(trace_id=trace_id, agent_run_id=run, ts=ts, text=text))


def test_append_under_cap_evicts_nothing():
    store = EpisodicLogStore(max_traces=5, now_fn=lambda: 1000.0)
    evicted = store.append(_env("t", "r", "run", "x1", ts=1000.0))
    assert evicted == []
    assert len(store.buffer("t", "r")) == 1


def test_count_cap_evicts_oldest_keeps_most_recent():
    store = EpisodicLogStore(max_traces=2, now_fn=lambda: 1000.0)
    store.append(_env("t", "r", "run", "x1", ts=1000.0))
    store.append(_env("t", "r", "run", "x2", ts=1001.0))
    evicted = store.append(_env("t", "r", "run", "x3", ts=1002.0))
    assert [e["trace_id"] for e in evicted] == ["x1"]
    assert [e["trace_id"] for e in store.buffer("t", "r")] == ["x2", "x3"]


def test_age_window_evicts_traces_older_than_48h():
    now = 1_000_000.0
    store = EpisodicLogStore(max_traces=100, max_age_seconds=48 * 3600, now_fn=lambda: now)
    # 49 hours old -> outside the 48h window -> evicted on next append
    evicted = store.append(_env("t", "r", "run", "stale", ts=now - 49 * 3600))
    assert [e["trace_id"] for e in evicted] == ["stale"]
    assert store.buffer("t", "r") == []


def test_groups_are_isolated_by_tenant_and_repo():
    store = EpisodicLogStore(max_traces=1, now_fn=lambda: 1000.0)
    store.append(_env("acme", "api", "r", "a1", ts=1000.0))
    store.append(_env("globex", "web", "r", "b1", ts=1000.0))
    # acme/api at cap 1 is untouched by globex/web traffic
    assert [e["trace_id"] for e in store.buffer("acme", "api")] == ["a1"]
    assert [e["trace_id"] for e in store.buffer("globex", "web")] == ["b1"]


def test_on_evict_callback_fires_with_group_and_evicted_traces():
    seen = []
    store = EpisodicLogStore(max_traces=1, now_fn=lambda: 1000.0,
                             on_evict=lambda t, r, traces: seen.append((t, r, [x["trace_id"] for x in traces])))
    store.append(_env("acme", "api", "r", "a1", ts=1000.0))
    store.append(_env("acme", "api", "r", "a2", ts=1001.0))  # evicts a1
    assert seen == [("acme", "api", ["a1"])]
