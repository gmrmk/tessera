"""SEC-6: keyed chain signing. With DLE_CHAIN_KEY set, a forged or truncated tail
must FAIL verify (the inverse of the purple-team forgery PoC). The keyless contrast
test documents WHY the key matters - without it, the same rewrite verifies clean."""
from __future__ import annotations

import hashlib
import json

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.store import GovernanceStore


def _sha(prev: str, body: str) -> str:
    return hashlib.sha256(f"{prev}|{body}".encode("utf-8")).hexdigest()


def _public_rewrite(store, org, events):
    """What a key-less attacker with DB write access can do: rewrite the whole tail
    (and the keyless anchor) using the PUBLIC sha256 algorithm - no HMAC key."""
    prev = "0" * 64
    seq = head_mac = None
    for seq, ev in enumerate(events, start=1):
        body = json.dumps(ev, sort_keys=True, separators=(",", ":"))
        head_mac = _sha(prev, body)
        store.conn.execute("UPDATE chain SET payload=?, prev_hash=?, entry_hash=? WHERE org=? AND seq=?",
                           (body, prev, head_mac, org, seq))
        prev = head_mac
    amac = _sha("anchor", f"{org}|{seq}|{head_mac}")  # keyless anchor the attacker can recompute
    store.conn.execute("UPDATE chain_anchor SET seq=?, head_mac=?, anchor_mac=? WHERE org=?",
                       (seq, head_mac, amac, org))
    store.conn.commit()


def test_keyed_chain_reports_signed_and_verifies(monkeypatch):
    monkeypatch.setenv("DLE_CHAIN_KEY", "an-out-of-db-signing-secret")
    c = GovernanceChain(GovernanceStore())
    c.append("acme", {"event": "real-1"})
    c.append("acme", {"event": "real-2"})
    v = c.verify("acme")
    assert v["ok"] is True and v["signed"] is True and v["entries"] == 2


def test_keyed_chain_detects_full_tail_forgery(monkeypatch):
    monkeypatch.setenv("DLE_CHAIN_KEY", "an-out-of-db-signing-secret")
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"event": "real-1"})
    c.append("acme", {"event": "real-2"})
    _public_rewrite(s, "acme", [{"event": "FORGED-1"}, {"event": "FORGED-2"}])
    assert c.verify("acme")["ok"] is False  # the HMAC the forger lacks makes it detectable


def test_keyless_chain_cannot_stop_full_tail_forgery():
    # the honest contrast: WITHOUT a key the same public rewrite verifies clean - which
    # is exactly why DLE_CHAIN_KEY is required to earn the "tamper-evident" claim.
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"event": "real-1"})
    c.append("acme", {"event": "real-2"})
    _public_rewrite(s, "acme", [{"event": "FORGED-1"}, {"event": "FORGED-2"}])
    v = c.verify("acme")
    assert v["ok"] is True and v["signed"] is False


def test_keyed_chain_detects_truncation(monkeypatch):
    monkeypatch.setenv("DLE_CHAIN_KEY", "an-out-of-db-signing-secret")
    s = GovernanceStore()
    c = GovernanceChain(s)
    for i in range(3):
        c.append("acme", {"i": i})
    assert c.verify("acme")["ok"]
    s.conn.execute("DELETE FROM chain WHERE org=? AND seq=?", ("acme", 3))  # truncate the tail
    s.conn.commit()
    v = c.verify("acme")
    assert v["ok"] is False and "trunc" in v["reason"].lower()  # anchor still points at seq 3


def test_keyed_chain_detects_truncation_to_zero(monkeypatch):
    # census n106: deleting EVERY chain row but leaving the signed anchor (truncation-to-zero)
    # must fail verify - the anchor still points at the old head while the chain is empty.
    monkeypatch.setenv("DLE_CHAIN_KEY", "an-out-of-db-signing-secret")
    s = GovernanceStore()
    c = GovernanceChain(s)
    for i in range(3):
        c.append("acme", {"i": i})
    s.conn.execute("DELETE FROM chain WHERE org=?", ("acme",))  # delete ALL rows, keep the anchor
    s.conn.commit()
    v = c.verify("acme")
    assert v["ok"] is False and "trunc" in v["reason"].lower()  # anchor/head mismatch, not ok


def test_key_file_signs_and_detects_forgery(monkeypatch, tmp_path):
    # census n137: the DLE_CHAIN_KEY_FILE production path - a valid key file signs the chain
    # (signed=True) and a forged tail still fails verify, exactly as the env-var key would.
    kf = tmp_path / "chain.key"
    kf.write_text("a-file-held-signing-secret")
    monkeypatch.delenv("DLE_CHAIN_KEY", raising=False)
    monkeypatch.setenv("DLE_CHAIN_KEY_FILE", str(kf))
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"event": "real-1"})
    c.append("acme", {"event": "real-2"})
    assert c.verify("acme")["signed"] is True
    _public_rewrite(s, "acme", [{"event": "FORGED-1"}, {"event": "FORGED-2"}])
    assert c.verify("acme")["ok"] is False  # forger lacks the file-held key


def test_empty_key_file_falls_back_to_keyless(monkeypatch, tmp_path):
    # census n137: an empty/whitespace key file resolves to keyless (signed=False), not a
    # zero-length "key" - the documented fallback when no real secret is present.
    kf = tmp_path / "empty.key"
    kf.write_text("   \n")  # whitespace-only -> stripped to empty -> keyless
    monkeypatch.delenv("DLE_CHAIN_KEY", raising=False)
    monkeypatch.setenv("DLE_CHAIN_KEY_FILE", str(kf))
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"event": "real-1"})
    assert c.verify("acme") == {"ok": True, "entries": 1, "signed": False}


def test_key_rotation_invalidates_prior_signatures(monkeypatch):
    # census n341: DEPLOY.md:69 - rotating the key makes prior entries fail verify (mac mismatch),
    # because their HMACs were computed under the old key. Pins the documented operator footgun.
    monkeypatch.setenv("DLE_CHAIN_KEY", "key-A")
    s = GovernanceStore()
    c = GovernanceChain(s)
    c.append("acme", {"event": "signed-under-A"})
    assert c.verify("acme")["ok"] is True
    monkeypatch.setenv("DLE_CHAIN_KEY", "key-B")  # rotate the signing key
    v = c.verify("acme")
    assert v["ok"] is False and "mac mismatch" in v["reason"].lower()
