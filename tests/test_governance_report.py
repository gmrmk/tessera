"""org_report - the org read: rollups, severity detail, and audit-trail integrity.

Covers the signed / keyless / broken integrity branches, the empty-findings and
empty-repos paths, the [SEV] detail formatting, the >50 detail-cap indicator
(item 291), and the signed rollback caveat (item 292).
"""
from __future__ import annotations

from _govfixtures import DIRTY

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.ingest import Attribution, ingest_change
from dual_log_engine.governance.report import org_report, org_summary
from dual_log_engine.governance.store import GovernanceStore


def _seeded():
    store = GovernanceStore()
    chain = GovernanceChain(store)
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"))
    return store, chain


def test_report_keyless_integrity_line(monkeypatch):
    monkeypatch.delenv("DLE_CHAIN_KEY", raising=False)
    store, chain = _seeded()
    out = org_report(store, chain, "acme")
    assert "# Agent-governance report - org: acme" in out
    assert "[OK]" in out
    assert "SHA-256 linked" in out
    assert "set DLE_CHAIN_KEY for tamper-evidence" in out


def test_report_signed_integrity_line_and_rollback_caveat(monkeypatch):
    monkeypatch.setenv("DLE_CHAIN_KEY", "test-key-1234567890")
    store = GovernanceStore()
    chain = GovernanceChain(store)
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"))
    out = org_report(store, chain, "acme")
    assert "tamper-evident chain intact, HMAC-signed" in out
    # item 292: the signed report must surface the rollback/external-witness caveat
    assert "external witness" in out
    assert "Limit:" in out


def test_report_broken_chain_line(monkeypatch):
    monkeypatch.delenv("DLE_CHAIN_KEY", raising=False)
    store, chain = _seeded()
    store._tamper_for_test("acme", 1, '{"x":1}')
    out = org_report(store, chain, "acme")
    assert "[BROKEN]" in out
    assert "may have been altered" in out


def test_report_empty_org_repos_none_and_no_findings():
    store = GovernanceStore()
    chain = GovernanceChain(store)
    out = org_report(store, chain, "nobody")
    assert "(none)" in out  # no repos
    assert "none surfaced by the current checks" in out


def test_report_severity_detail_formatting():
    store, chain = _seeded()
    out = org_report(store, chain, "acme")
    # the [SEV] detail line shape: [CRITICAL] <check_id> | file:line | framework | `snippet`
    assert "## Safety findings" in out
    assert "### Detail" in out
    assert "[CRITICAL]" in out
    assert "secret-hardcoded" in out
    assert " | " in out


def test_report_detail_cap_indicator(monkeypatch):
    monkeypatch.delenv("DLE_CHAIN_KEY", raising=False)
    store, chain = _seeded()
    # add many low findings to exceed the 50-row detail cap (item 291)
    cid = store.add_change("acme", "api", "sha9", "a", "claude", "s")
    for i in range(60):
        store.add_finding(cid, "acme", "api", {
            "check_id": "secret-hardcoded", "category": "security", "severity": "LOW",
            "file": "f.py", "line": i, "framework": "owasp", "clause": "",
            "framework_url": "", "snippet": "x", "verified": True})
    out = org_report(store, chain, "acme")
    s = org_summary(store, chain, "acme")
    assert s["findings"]  # sanity
    assert "(showing first 50 of" in out


def test_report_never_leaks_redacted_secret():
    store, chain = _seeded()
    out = org_report(store, chain, "acme")
    assert "A1B2C3D4E5" not in out


def test_org_summary_contract_keys_repos_and_agent_coalescing():
    # RPT-2: the machine-readable rollup that also backs the CLI --json path (IFC-3).
    # Exact key set, repos sorted+deduped, and a None agent coalesced to 'unknown'.
    store = GovernanceStore()
    chain = GovernanceChain(store)
    # two changes in repo "api", one in "web" (out of alpha order) to prove sort+dedupe;
    # add_change is used directly so we can plant an agent=None row.
    store.add_change("acme", "web", None, "alice", "claude", "s")
    store.add_change("acme", "api", None, "bob", None, "s")  # agent=None -> 'unknown'
    store.add_change("acme", "api", None, "carol", "claude", "s")
    s = org_summary(store, chain, "acme")
    assert set(s) == {"org", "changes", "repos", "by_agent", "severity_counts", "findings", "chain"}
    assert s["changes"] == 3
    assert s["repos"] == ["api", "web"]  # sorted + de-duplicated
    assert s["by_agent"] == {"claude": 2, "unknown": 1}  # None agent lands in 'unknown'
