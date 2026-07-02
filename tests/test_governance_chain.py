"""Tamper-evident chain - append, integrity, tamper-detection, per-org isolation."""
from __future__ import annotations

from dual_log_engine.governance.chain import GENESIS, GovernanceChain, _key, _mac
from dual_log_engine.governance.store import GovernanceStore


def test_append_then_verify_intact():
    c = GovernanceChain(GovernanceStore())
    c.append("acme", {"a": 1})
    c.append("acme", {"a": 2})
    # ok:True here is integrity-of-link only; keyless does NOT detect a full-tail forger -
    # see test_governance_chain_signing.py (test_keyless_chain_cannot_stop_full_tail_forgery).
    assert c.verify("acme") == {"ok": True, "entries": 2, "signed": False}  # keyless back-compat


def test_tampering_a_past_entry_is_detected():
    store = GovernanceStore()
    c = GovernanceChain(store)
    c.append("acme", {"a": 1})
    c.append("acme", {"a": 2})
    c.append("acme", {"a": 3})
    store._tamper_for_test("acme", 2, '{"a":99}')  # silently edit entry 2's payload
    res = c.verify("acme")
    assert res["ok"] is False and res["broken_at"] == 2


def test_chain_is_isolated_per_org():
    c = GovernanceChain(GovernanceStore())
    c.append("acme", {"x": 1})
    c.append("globex", {"y": 1})
    assert c.verify("acme")["entries"] == 1
    assert c.verify("globex")["entries"] == 1
    assert c.verify("acme")["ok"] and c.verify("globex")["ok"]


def test_append_writes_entry_and_anchor_atomically():
    # census C2: the chain row and its anchor are written in ONE transaction, so the anchor
    # can never lag the head - which would make verify() falsely report "truncated".
    store = GovernanceStore()
    c = GovernanceChain(store)
    for i in range(3):
        c.append("acme", {"i": i})
        seq, head_mac = store.chain_head("acme")
        anchor = store.get_anchor("acme")
        assert anchor["seq"] == seq and anchor["head_mac"] == head_mac
    assert c.verify("acme")["ok"]


def test_append_rejects_non_dict_payload():
    # census n98: validate at the boundary - a non-dict payload must fail fast (TypeError),
    # not silently canonicalize to a JSON scalar and get stored.
    import pytest
    c = GovernanceChain(GovernanceStore())
    with pytest.raises(TypeError):
        c.append("acme", ["not", "a", "dict"])
    with pytest.raises(TypeError):
        c.append("acme", "raw-string")


def test_file_backed_chain_survives_reopen(tmp_path):
    # census n136: a file-backed store must persist the chain across close/reopen (exercises
    # the WAL pragma, parent-dir mkdir, and the reopen path that the :memory: tests never hit).
    db = tmp_path / "nested" / "g.db"
    s1 = GovernanceStore(db)
    c1 = GovernanceChain(s1)
    c1.append("acme", {"a": 1})
    c1.append("acme", {"a": 2})
    assert c1.verify("acme")["ok"]
    s1.close()

    s2 = GovernanceStore(db)              # reopen a NEW store on the same file
    c2 = GovernanceChain(s2)
    assert c2.verify("acme") == {"ok": True, "entries": 2, "signed": False}
    assert len(s2.chain_rows("acme")) == 2
    s2.close()


def test_verify_reports_sequence_gap_on_deleted_middle_row():
    # census n138: deleting a middle chain row leaves a seq hole -> the distinct "sequence gap" reason.
    s = GovernanceStore()
    c = GovernanceChain(s)
    for i in range(3):
        c.append("acme", {"i": i})
    s.conn.execute("DELETE FROM chain WHERE org=? AND seq=?", ("acme", 2))
    s.conn.commit()
    res = c.verify("acme")
    assert res["ok"] is False and res["reason"] == "sequence gap" and res["broken_at"] == 3


def test_verify_reports_prev_hash_mismatch_on_corrupted_link():
    # census n138: corrupting a stored prev_hash (without touching seq) hits the prev_hash-mismatch
    # branch, a distinct reason from the mac-mismatch one the tamper test exercises.
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"a": 1})
    c.append("acme", {"a": 2})
    s.conn.execute("UPDATE chain SET prev_hash=? WHERE org=? AND seq=?", ("f" * 64, "acme", 2))
    s.conn.commit()
    res = c.verify("acme")
    assert res["ok"] is False and "prev_hash mismatch" in res["reason"] and res["broken_at"] == 2


def test_stored_payload_is_exactly_the_macd_body():
    # census n259: pin the recompute-panel contract - the rendered/stored chain.payload IS the
    # body that was MAC'd, so _mac(key, prev_hash, payload) reproduces the stored entry_hash.
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"a": 1})
    c.append("acme", {"a": 2})
    key = _key()  # keyless here (no DLE_CHAIN_KEY), matching how these rows were signed
    prev = GENESIS
    for row in s.chain_rows("acme"):
        assert row["prev_hash"] == prev
        assert _mac(key, row["prev_hash"], row["payload"]) == row["entry_hash"]
        prev = row["entry_hash"]
