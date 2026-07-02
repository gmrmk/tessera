"""Dashboard - rollups, HTML render, redaction-in-HTML, org isolation, chain status."""
from __future__ import annotations

from _govfixtures import DIRTY

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.dashboard import (
    _TWO_SIGNAL,
    _coverage,
    _safe_href,
    _traceability,
    dashboard_data,
    render_dashboard,
)
from dual_log_engine.governance.ingest import Attribution, ingest_change
from dual_log_engine.governance.safety.checks import CHECKS
from dual_log_engine.governance.store import GovernanceStore


def _seeded():
    store = GovernanceStore()
    chain = GovernanceChain(store)
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"))
    return store, chain


def test_dashboard_data_rollups():
    store, chain = _seeded()
    d = dashboard_data(store, chain, "acme")
    assert d["org"] == "acme"
    assert d["totals"]["changes"] == 1
    assert d["totals"]["findings"] >= 2
    assert d["by_agent"].get("claude") == 1
    assert d["by_severity"].get("CRITICAL", 0) >= 1  # the hard-coded secret
    assert d["chain"]["ok"]


def test_render_html_has_org_findings_and_chain():
    store, chain = _seeded()
    doc = render_dashboard(store, chain, "acme")
    assert doc.startswith("<!doctype html>")
    assert "acme" in doc
    assert "CRITICAL" in doc and "secret-hardcoded" in doc
    assert "intact" in doc  # chain-intact banner


def test_render_redacts_and_never_leaks_the_secret():
    store, chain = _seeded()
    doc = render_dashboard(store, chain, "acme")
    assert "REDACTED" in doc
    assert "A1B2C3D4E5" not in doc  # the fake key fragment never reaches the HTML


def test_empty_org_renders_cleanly():
    store = GovernanceStore()
    chain = GovernanceChain(store)
    doc = render_dashboard(store, chain, "nobody")
    assert "<!doctype html>" in doc
    assert "no findings" in doc.lower() or "none" in doc.lower()


def test_dashboard_is_org_isolated():
    store, chain = _seeded()
    ingest_change(store, chain, "globex", "secretrepo", DIRTY, Attribution("bob", "gpt"))
    doc = render_dashboard(store, chain, "acme")
    assert "globex" not in doc and "secretrepo" not in doc


def test_broken_chain_is_surfaced_in_dashboard():
    store, chain = _seeded()
    store._tamper_for_test("acme", 1, '{"x":1}')
    doc = render_dashboard(store, chain, "acme")
    assert "BROKEN" in doc


# --- item 260: the two-signal prose map must stay bound to the real registry ---

def test_two_signal_keys_match_registry_exactly():
    # Adding/removing/renaming a check must fail CI here rather than silently
    # falling back to the generic prose at render time.
    assert set(_TWO_SIGNAL) == {c.id for c in CHECKS}


# --- item 266: an undocumented check id renders an explicit marker, not fake prose ---

def test_unknown_check_id_renders_not_documented_marker():
    findings = [{
        "check_id": "totally-new-check", "severity": "HIGH", "category": "security",
        "file": "x.py", "line": 1, "framework": "owasp", "clause": "", "framework_url": "",
        "snippet": "evidence", "change_id": None,
    }]
    from dual_log_engine.governance.dashboard import _findings_list
    html = _findings_list(findings, {})
    assert "two-signal reasoning not documented for this check id" in html
    # the old fabricated generic prose must not appear
    assert "an independent check confirmed it" not in html


# --- item 270: an out-of-registry finding must not inflate the coverage denominator ---

def test_out_of_registry_finding_does_not_inflate_total():
    registry_size = len(CHECKS)
    cov = _coverage({"secret-hardcoded": 1, "not-a-real-check": 3})
    # total stays the true registry size; ran counts only registry checks that fired
    assert cov["total"] == registry_size
    assert cov["ran"] == 1
    off = [r for r in cov["checks"] if r["id"] == "not-a-real-check"]
    assert off and off[0]["in_registry"] is False


def test_limits_line_total_matches_registry_with_off_registry_finding():
    store, chain = _seeded()
    # inject an out-of-registry finding straight into the store
    cid = store.add_change("acme", "api", "sha1", "a", "claude", "s")
    store.add_finding(cid, "acme", "api", {
        "check_id": "ghost-check", "category": "security", "severity": "LOW",
        "file": "g.py", "line": 1, "framework": "owasp", "clause": "",
        "framework_url": "", "snippet": "x", "verified": True})
    doc = render_dashboard(store, chain, "acme")
    assert f"the {len(CHECKS)} checks in" in doc


# --- item 280: a javascript: framework_url must not become a clickable href ---

def test_safe_href_only_allows_http_schemes():
    assert _safe_href("https://example.com").startswith("https://")
    assert _safe_href("http://example.com").startswith("http://")
    assert _safe_href("javascript:alert(1)") is None
    assert _safe_href("data:text/html,x") is None
    assert _safe_href("") is None


def test_render_does_not_emit_javascript_href():
    store, chain = _seeded()
    cid = store.add_change("acme", "api", "sha1", "a", "claude", "s")
    store.add_finding(cid, "acme", "api", {
        "check_id": "secret-hardcoded", "category": "security", "severity": "LOW",
        "file": "g.py", "line": 1, "framework": "owasp", "clause": "evil-clause",
        "framework_url": "javascript:alert(1)", "snippet": "x", "verified": True})
    doc = render_dashboard(store, chain, "acme")
    # the dangerous scheme is never emitted inside an href (it may still appear as
    # inert escaped plain text, which is safe); no clickable javascript: link.
    assert 'href="javascript:' not in doc
    assert "<a href=\"javascript" not in doc


# --- item 286: seq map is first-seen and shared between trace and ledref ---

def test_traceability_uses_caller_seq_map_verbatim():
    changes = [{"id": 7, "repo": "api", "agent": "claude", "author": "a", "sha": "z"}]
    # caller-provided first-seen policy: change 7 -> seq 2
    groups = _traceability(changes, [], {7: 2})
    assert groups[0]["chain_seq"] == 2


def test_dashboard_trace_seq_matches_ledref_seq():
    store, chain = _seeded()
    d = dashboard_data(store, chain, "acme")
    # the trace badge seq and the seq_by_change map (used for the finding ledref) agree
    for g in d["traceability"]:
        assert g["chain_seq"] == d["seq_by_change"].get(g["change_id"])


# --- item 287: rows after a break do not render a green 'links to seq' badge ---

def test_rows_after_break_are_not_shown_as_linked():
    store, chain = _seeded()
    # build a multi-entry chain, then break the FIRST entry so later rows are void
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("a", "claude"))
    store._tamper_for_test("acme", 1, '{"x":1}')
    doc = render_dashboard(store, chain, "acme")
    assert "BROKEN" in doc
    # a later row whose local prev==entry must read as void, never green 'links to seq'
    assert "void after break" in doc
