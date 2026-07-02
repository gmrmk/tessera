"""Ingestion  -  diff parsing, attribution, agnostic scan, isolation, redaction, report."""
from __future__ import annotations

from _govfixtures import CLEAN, DIRTY

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.ingest import (
    Attribution,
    infer_attribution,
    ingest_change,
    parse_diff,
)
from dual_log_engine.governance.report import org_report
from dual_log_engine.governance.store import GovernanceStore


def _engine():
    store = GovernanceStore()
    return store, GovernanceChain(store)


def test_parse_diff_extracts_added_lines_with_paths():
    files = parse_diff(CLEAN)
    assert files and files[0][0] == "app/util.py"
    assert any("def mul" in text for _, text in files[0][1])


def test_ingest_records_change_and_scans_findings():
    store, chain = _engine()
    res = ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"))
    assert res["n_findings"] >= 2  # secret + sql at minimum
    row = store.changes("acme")[0]
    assert row["agent"] == "claude" and row["author"] == "alice"


def test_ingest_blank_org_raises_valueerror():
    # LOW: the CLI path never validated org blankness/type (the store did, but only deep inside,
    # after parse_diff). ingest_change validates the tenant key UP FRONT so a blank/invalid org
    # fails cleanly with ValueError before any diff parsing. Passing diff=None proves the order:
    # without the up-front check, parse_diff(None) raises TypeError first, not ValueError.
    import pytest
    store, chain = _engine()
    with pytest.raises(ValueError):
        ingest_change(store, chain, "   ", "api", None, Attribution("a", "claude"))
    with pytest.raises(ValueError):  # also holds for a normal (string) diff
        ingest_change(store, chain, "   ", "api", DIRTY, Attribution("a", "claude"))


def test_clean_change_yields_no_findings():
    store, chain = _engine()
    res = ingest_change(store, chain, "acme", "api", CLEAN, Attribution("bob", "gpt"))
    assert res["n_findings"] == 0


def test_agent_agnostic_same_change_scans_identically():
    store, chain = _engine()
    a = ingest_change(store, chain, "acme", "api", DIRTY, Attribution("x", "claude"))
    b = ingest_change(store, chain, "acme", "api", DIRTY, Attribution("y", "human"))
    assert {f.check_id for f in a["findings"]} == {f.check_id for f in b["findings"]}


def test_cross_org_isolation():
    store, chain = _engine()
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    ingest_change(store, chain, "globex", "web", DIRTY, Attribution("b", "human"))
    assert all(c["org"] == "acme" for c in store.changes("acme"))
    assert all(f["org"] == "acme" for f in store.findings("acme"))
    assert chain.verify("acme")["entries"] == 1  # globex's entry is on its own chain


def test_secret_is_redacted_before_storage():
    store, chain = _engine()
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    secret_rows = [f for f in store.findings("acme") if f["check_id"] == "secret-hardcoded"]
    assert secret_rows
    assert all("REDACTED" in r["snippet"] and "A1B2C3D4E5" not in r["snippet"] for r in secret_rows)


def test_chain_payload_carries_redacted_findings_no_snippet():
    # ING-1: the chain payload records each finding as {check, severity, file, line} ONLY -
    # no snippet reaches the ledger, so the tamper-evident trail cannot leak a secret.
    import json
    store, chain = _engine()
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    payload = json.loads(store.chain_rows("acme")[0]["payload"])
    assert payload["findings"], "expected at least one finding in the payload"
    for f in payload["findings"]:
        assert set(f) == {"check", "severity", "file", "line"}  # note: 'check', not 'check_id'
    # the fixture's secret fragment must appear nowhere in the serialized ledger entry.
    assert "A1B2C3D4E5" not in store.chain_rows("acme")[0]["payload"]


def test_infer_attribution_from_commit_trailer():
    a = infer_attribution("fix bug\n\nCo-Authored-By: Claude <noreply@anthropic.com>", "alice")
    assert a.agent == "claude" and a.author == "alice"
    assert infer_attribution("plain human commit").agent == "human"


def test_org_report_rolls_up():
    store, chain = _engine()
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    report = org_report(store, chain, "acme")
    assert "acme" in report
    assert "Safety findings" in report
    assert "chain intact" in report  # honest in both signed + keyless modes
