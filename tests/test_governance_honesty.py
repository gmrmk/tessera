"""SEC-10: the user-facing language must not over-claim. Keyless mode (no
DLE_CHAIN_KEY) must NOT assert cryptographic tamper-evidence, redaction is labelled
best-effort, and the claim is only made once the key earns it. The product's whole
value is honesty - so the words track exactly what the code can cash."""
from __future__ import annotations

from _govfixtures import DIRTY

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.dashboard import render_dashboard
from dual_log_engine.governance.ingest import Attribution, ingest_change
from dual_log_engine.governance.report import org_report
from dual_log_engine.governance.store import GovernanceStore


def _seeded():
    s = GovernanceStore()
    c = GovernanceChain(s)
    ingest_change(s, c, "acme", "api", DIRTY, Attribution("a", "claude"))
    return s, c


def test_keyless_dashboard_does_not_over_claim():
    s, c = _seeded()
    html = render_dashboard(s, c, "acme")
    assert "best-effort" in html                       # redaction not over-claimed
    assert "DLE_CHAIN_KEY" in html                      # honest path to real tamper-evidence
    assert "Tamper-evident chain intact &mdash;" not in html  # not claimed without a key


def test_keyed_dashboard_earns_the_claim(monkeypatch):
    monkeypatch.setenv("DLE_CHAIN_KEY", "an-out-of-db-signing-secret")
    s, c = _seeded()
    html = render_dashboard(s, c, "acme")
    assert "Tamper-evident chain intact" in html        # now earned (HMAC-signed)


def test_keyless_report_points_to_the_key():
    s, c = _seeded()
    assert "set DLE_CHAIN_KEY" in org_report(s, c, "acme")
