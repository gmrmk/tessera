"""GovernanceStore direct-level coverage - severity_counts + add_finding contract (EVD-4).

The store's severity_counts() and add_finding() are only exercised incidentally by the
ingest/report/dashboard tests; here we pin their contract directly so a regression surfaces
at the storage layer rather than three layers up.
"""
from __future__ import annotations

import pytest

from dual_log_engine.governance.store import GovernanceStore


def _finding(sev: str) -> dict:
    return {
        "check_id": "secret-hardcoded", "category": "security", "severity": sev,
        "file": "f.py", "line": 1, "snippet": "REDACTED",
        "framework": "owasp", "framework_url": "", "clause": "", "verified": True,
    }


def test_severity_counts_tallies_by_severity():
    store = GovernanceStore()
    cid = store.add_change("acme", "api", None, "alice", "claude", "s")
    for sev in ("CRITICAL", "CRITICAL", "HIGH", "LOW"):
        store.add_finding(cid, "acme", "api", _finding(sev))
    assert store.severity_counts("acme") == {"CRITICAL": 2, "HIGH": 1, "LOW": 1}


def test_severity_counts_empty_org_is_empty_dict():
    assert GovernanceStore().severity_counts("nobody") == {}


def test_severity_counts_is_org_scoped():
    store = GovernanceStore()
    a = store.add_change("acme", "api", None, "a", "claude", "s")
    b = store.add_change("globex", "web", None, "b", "human", "s")
    store.add_finding(a, "acme", "api", _finding("HIGH"))
    store.add_finding(b, "globex", "web", _finding("LOW"))
    assert store.severity_counts("acme") == {"HIGH": 1}  # globex's LOW is not counted


def test_add_finding_requires_severity():
    store = GovernanceStore()
    cid = store.add_change("acme", "api", None, "a", "claude", "s")
    bad = _finding("HIGH")
    del bad["severity"]  # a finding with no severity is a programming error, not a silent 0
    with pytest.raises(KeyError):
        store.add_finding(cid, "acme", "api", bad)
