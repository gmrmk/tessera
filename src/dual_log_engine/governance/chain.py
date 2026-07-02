"""GovernanceChain - the append-only, integrity-protected audit ledger.

Each entry stores `entry_hash = MAC(prev_hash | canonical(payload))`. The MAC is:

  - **keyed (HMAC-SHA256)** when a signing key is configured out-of-DB via
    `DLE_CHAIN_KEY` (or a file path in `DLE_CHAIN_KEY_FILE`). A write-capable
    attacker who does NOT hold the key cannot recompute a valid MAC for an edited
    payload, so any rewrite of the tail is detectable - this is what makes the
    ledger tamper-evident against an insider with database write access, BUT ONLY in
    this keyed mode. Without DLE_CHAIN_KEY (keyless mode below) it is not tamper-evident.
  - **keyless (SHA-256)** as a back-compat fallback when no key is set. This detects
    accidental edits and a naive single-row change, but NOT a key-less forger who
    rewrites the whole tail with the public hash. `verify()` reports `signed=False`
    in this mode so the honesty is explicit - a keyless chain does not claim more
    than it earns.

A signed **anchor** (the head seq + head MAC, itself MAC'd) is persisted per org so
that truncation / rollback of the tail is caught: deleting recent entries leaves the
anchor pointing at a head that no longer exists. An attacker without the key cannot
forge a matching anchor for the shortened chain.

Honest limitation: a full rollback in which the attacker restores BOTH the chain and
a previously-valid anchor to a consistent earlier state is not detectable locally -
that requires an external witness (a published head, a notary). Documented, not hidden.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from .store import GovernanceStore, _tenant_key

GENESIS = "0" * 64
# Tie the 64-zero genesis constant to the actual MAC digest width; if _mac's digest
# ever changes (e.g. sha512), this fails loud at import instead of silently mismatching.
# An explicit raise (not assert) so the check survives `python -O`, which strips asserts.
if len(GENESIS) != len(hashlib.sha256(b"").hexdigest()):
    raise RuntimeError("GENESIS width must match the MAC digest width")


def _key() -> bytes | None:
    """The signing key, held OUT of the audit DB (env var or a key file). None = keyless.

    Precedence: DLE_CHAIN_KEY (env value) takes precedence over DLE_CHAIN_KEY_FILE when
    BOTH are set - the file is silently ignored in that case (rotate via the same source
    you configured, or the file change will not take effect)."""
    k = os.environ.get("DLE_CHAIN_KEY")
    if k:
        return k.encode("utf-8")
    kf = os.environ.get("DLE_CHAIN_KEY_FILE")
    if kf and Path(kf).exists():
        data = Path(kf).read_bytes().strip()
        if data:
            return data
    return None


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _mac(key: bytes | None, prev: str, body: str) -> str:
    msg = f"{prev}|{body}".encode("utf-8")
    if key is None:
        return hashlib.sha256(msg).hexdigest()                 # keyless: forgeable, signed=False
    return hmac.new(key, msg, hashlib.sha256).hexdigest()      # keyed: unforgeable without the key


def _anchor_mac(key: bytes | None, org: str, seq: int, head_mac: str) -> str:
    return _mac(key, "anchor", f"{org}|{seq}|{head_mac}")


class GovernanceChain:
    def __init__(self, store: GovernanceStore) -> None:
        self.store = store

    def append(self, org: str, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")  # fail fast at the boundary, before canonicalizing
        org = _tenant_key(org)
        key = _key()
        seq, prev = self.store.chain_head(org)
        prev_hash = prev or GENESIS
        seq += 1
        body = _canonical(payload)
        entry_mac = _mac(key, prev_hash, body)
        self.store.append_chain_and_anchor(
            org, seq, prev_hash, body, entry_mac, _anchor_mac(key, org, seq, entry_mac))
        return {"seq": seq, "entry_hash": entry_mac}

    def verify(self, org: str) -> dict:
        """Walk the chain + check the signed anchor. Returns {ok, entries, signed} or
        {ok: False, broken_at, reason, signed}."""
        org = _tenant_key(org)
        key = _key()
        signed = key is not None
        rows = self.store.chain_rows(org)
        prev_hash = GENESIS
        for expected_seq, row in enumerate(rows, start=1):
            if row["seq"] != expected_seq:
                return {"ok": False, "broken_at": row["seq"], "reason": "sequence gap", "signed": signed}
            if row["prev_hash"] != prev_hash:
                return {"ok": False, "broken_at": row["seq"],
                        "reason": "prev_hash mismatch (entry inserted/removed)", "signed": signed}
            # MAC the STORED canonical body verbatim (row["payload"] is exactly what append() MAC'd
            # and persisted); never re-run _canonical() here, or json/library drift could change the
            # bytes and cause a FALSE tamper report on an untouched chain.
            if _mac(key, row["prev_hash"], row["payload"]) != row["entry_hash"]:
                return {"ok": False, "broken_at": row["seq"],
                        "reason": "payload tampered (mac mismatch)", "signed": signed}
            prev_hash = row["entry_hash"]

        head_seq = rows[-1]["seq"] if rows else 0
        head_mac = rows[-1]["entry_hash"] if rows else GENESIS
        anchor = self.store.get_anchor(org)
        if anchor is None:
            if rows and signed:  # a signed chain must carry its anchor; absence is suspicious
                return {"ok": False, "broken_at": head_seq, "reason": "missing signed anchor", "signed": True}
            return {"ok": True, "entries": len(rows), "signed": signed}
        if _anchor_mac(key, org, anchor["seq"], anchor["head_mac"]) != anchor["anchor_mac"]:
            return {"ok": False, "broken_at": head_seq, "reason": "anchor signature invalid", "signed": signed}
        if anchor["seq"] != head_seq or anchor["head_mac"] != head_mac:
            return {"ok": False, "broken_at": head_seq,
                    "reason": "chain truncated or rolled back (anchor/head mismatch)", "signed": signed}
        return {"ok": True, "entries": len(rows), "signed": signed}
