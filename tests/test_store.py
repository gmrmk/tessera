"""SqliteStore  -  atomic merge, indexed pre-filter, episodic eviction, persistence."""
from __future__ import annotations

import tempfile
from pathlib import Path

from dual_log_engine.envelope import Entity, Relation
from dual_log_engine.store import SqliteStore


def _entity(name, level="LOW", desc="d", etype="COMPONENT") -> Entity:
    return Entity(entity_name=name, entity_type=etype, description=desc, level=level)


def _relation(src, tgt, rtype="CAUSES", level="LOW", desc="d", weight=1) -> Relation:
    return Relation(source=src, target=tgt, relation_type=rtype, description=desc, weight=weight, level=level)


def test_upsert_entity_inserts_then_merges():
    s = SqliteStore()
    s.upsert_entity("t", "r", _entity("auth.py", level="LOW", desc="first"))
    s.upsert_entity("t", "r", _entity("auth.py", level="HIGH", desc="second"))
    node = s.entity("t", "r", "auth.py")
    assert node["level"] == "HIGH"  # elevated
    assert "first" in node["description"] and "second" in node["description"]  # blended


def test_blend_skips_already_contained_text():
    s = SqliteStore()
    s.upsert_entity("t", "r", _entity("x", desc="same"))
    s.upsert_entity("t", "r", _entity("x", desc="same"))
    assert s.entity("t", "r", "x")["description"] == "same"  # not duplicated


def test_duplicate_relation_increments_weight():
    s = SqliteStore()
    s.upsert_relation("t", "r", _relation("a", "b", desc="first"))
    s.upsert_relation("t", "r", _relation("a", "b", desc="second"))
    edge = s.relation("t", "r", "a", "b", "CAUSES")
    assert edge["weight"] == 2
    assert "first" in edge["description"] and "second" in edge["description"]


def test_fetch_isolates_by_tenant_and_filters_by_level():
    s = SqliteStore()
    s.upsert_entity("acme", "api", _entity("shared", level="LOW"))
    s.upsert_entity("acme", "api", _entity("high1", level="HIGH"))
    s.upsert_entity("globex", "api", _entity("shared", level="LOW"))  # same name, other tenant

    ents, _ = s.fetch("acme", "api")  # HYBRID
    assert {e["entity_name"] for e in ents} == {"shared", "high1"}
    assert all(e["tenant_id"] == "acme" for e in ents)  # zero globex leakage

    low, _ = s.fetch("acme", "api", "LOW")
    high, _ = s.fetch("acme", "api", "HIGH")
    assert {e["entity_name"] for e in low} == {"shared"}
    assert {e["entity_name"] for e in high} == {"high1"}


def test_episodic_due_by_count_threshold():
    s = SqliteStore()
    for i in range(3):
        s.add_trace("t", "r", "run", f"x{i}", ts=1000.0 + i, text=f"line {i}")
    # keep newest 2, so the oldest 1 is due (huge age window -> count drives it)
    due = s.due_traces("t", "r", max_traces=2, max_age_seconds=10**9, now=2000.0)
    assert [d["trace_id"] for d in due] == ["x0"]


def test_episodic_due_by_age_window():
    s = SqliteStore()
    now = 1_000_000.0
    s.add_trace("t", "r", "run", "stale", ts=now - 49 * 3600, text="old")
    s.add_trace("t", "r", "run", "fresh", ts=now - 60, text="new")
    due = s.due_traces("t", "r", max_traces=100, max_age_seconds=48 * 3600, now=now)
    assert [d["trace_id"] for d in due] == ["stale"]


def test_delete_traces_removes_them():
    s = SqliteStore()
    s.add_trace("t", "r", "run", "x0", ts=1.0, text="a")
    rows = s.group_traces("t", "r")
    s.delete_traces([r["id"] for r in rows])
    assert s.buffer_count("t", "r") == 0


def test_cache_set_and_get():
    s = SqliteStore()
    assert s.get_cache("t", "r", "HIGH") is None
    s.set_cache("t", "r", "HIGH", "rendered")
    assert s.get_cache("t", "r", "HIGH") == "rendered"


def test_state_persists_to_a_file_across_reopen():
    db = Path(tempfile.mkdtemp(prefix="dle-store-")) / "memory.db"
    s1 = SqliteStore(db)
    s1.upsert_entity("t", "r", _entity("auth.py"))
    s1.close()
    s2 = SqliteStore(db)  # a separate process would open it the same way
    assert s2.entity("t", "r", "auth.py") is not None
