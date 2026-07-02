"""End-to-end governance self-check: ingest -> scan -> trail -> report -> tamper-detect.

    python -m dual_log_engine.governance.demo

Deterministic, no network. The "bad code" fixtures are assembled from fragments
so this file's own source doesn't contain a contiguous planted secret (the same
false-positive class the safety engine's verify() step exists to drop).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .chain import GovernanceChain
from .ingest import Attribution, ingest_change
from .report import org_report
from .store import GovernanceStore

_FAKE_KEY = "sk-" + "abc123def456ghi789jkl012mno345pqr"  # fake, > 20 chars
_SQL = 'cur.execute(f"SELECT * FROM users WHERE id = {' + 'uid}")'

DIRTY = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -1,2 +1,5 @@\n"
    " import sqlite3\n"
    '+token = "' + _FAKE_KEY + '"\n'
    "+def get_user(cur, uid):\n"
    "+    return " + _SQL + "\n"
)

CLEAN = (
    "--- a/app/util.py\n"
    "+++ b/app/util.py\n"
    "@@ -1,2 +1,4 @@\n"
    " def add(a, b):\n"
    "     return a + b\n"
    "+def mul(a, b):\n"
    "+    return a * b\n"
)


def main(db=None) -> None:
    if db is None:
        db = Path(tempfile.mkdtemp(prefix="dle-gov-")) / "governance.db"
    store = GovernanceStore(db)
    chain = GovernanceChain(store)

    # 1) a dirty change made by Claude -> both planted issues fire, grounded
    res = ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"), sha="abc123")
    fired = {f.check_id for f in res["findings"]}
    assert "secret-hardcoded" in fired and "sql-injection" in fired, fired
    assert all(f.framework for f in res["findings"]), "every finding must cite a source"
    secret = next(f for f in res["findings"] if f.check_id == "secret-hardcoded")
    assert "REDACTED" in secret.snippet and _FAKE_KEY not in secret.snippet, "secret must be redacted"

    # 2) a clean change made by GPT -> zero findings (the two-signal gate drops noise)
    res2 = ingest_change(store, chain, "acme", "api", CLEAN, Attribution("bob", "gpt"))
    assert res2["n_findings"] == 0, res2

    # 3) AGENT-AGNOSTIC: the same dirty change by a human scans identically
    res3 = ingest_change(store, chain, "acme", "api", DIRTY, Attribution("carol", "human"))
    assert {f.check_id for f in res3["findings"]} == fired

    # 4) cross-org isolation
    ingest_change(store, chain, "globex", "web", DIRTY, Attribution("dan", "cursor"))
    assert all(c["org"] == "acme" for c in store.changes("acme"))

    # 5) the org report, while the chain is still intact. "chain intact" is the honest
    # substring in BOTH signed and keyless modes (the report forks its wording on
    # whether DLE_CHAIN_KEY is set), so the self-check passes with or without a key.
    report = org_report(store, chain, "acme")
    assert "chain intact" in report

    # 6) integrity holds; then prove a silent edit is DETECTED
    assert chain.verify("acme")["ok"]
    store._tamper_for_test("acme", 1, '{"silently":"edited"}')
    broken = chain.verify("acme")
    assert not broken["ok"] and broken["broken_at"] == 1, broken

    print("dle-governance self-check")
    print(f"  dirty change (claude): {len(res['findings'])} findings -> {sorted(fired)}")
    print(f"  clean change  (gpt):   {res2['n_findings']} findings")
    print(f"  same change  (human):  {len(res3['findings'])} findings  (agent-agnostic: identical)")
    print(f"  isolation: acme = {len(store.changes('acme'))} change(s); globex kept separate")
    print(f"  secret redacted in storage: {secret.snippet!r}")
    print(f"  tamper DETECTED at chain entry {broken['broken_at']}: {broken['reason']}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
