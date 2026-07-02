"""Compliance - cited control mapping, mechanism controls, honesty, integrity, isolation."""
from __future__ import annotations

from _govfixtures import CLEAN, DIRTY

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.compliance import (
    COMPLIANCE_FRAMEWORKS,
    MECHANISM_CONTROLS,
    PENDING_REGIMES,
    compliance_data,
    compliance_report,
)
from dual_log_engine.governance.ingest import Attribution, ingest_change
from dual_log_engine.governance.store import GovernanceStore


def _seeded():
    store = GovernanceStore()
    chain = GovernanceChain(store)
    ingest_change(store, chain, "acme", "api", DIRTY, Attribution("alice", "claude"))
    return store, chain


def test_findings_map_to_cited_control_areas():
    store, chain = _seeded()
    d = compliance_data(store, chain, "acme")
    assert d["findings"] >= 2
    assert d["control_areas"]
    assert all(ca["url"] for ca in d["control_areas"])  # every control area is cited
    assert len(d["mechanism_controls"]) >= 3
    assert d["control_coverage"] >= 1
    assert d["chain"]["ok"]
    assert d["pending_regimes"]  # broader regimes listed honestly, not asserted


def test_only_verified_citations_ship():
    store, chain = _seeded()
    d = compliance_data(store, chain, "acme")
    for ca in d["control_areas"]:
        assert ca["url"].startswith("http")
    for mc in d["mechanism_controls"]:
        assert mc["framework_url"].startswith("http")  # nothing ships ungrounded


def test_report_is_cited_and_honest():
    store, chain = _seeded()
    r = compliance_report(store, chain, "acme")
    assert "Compliance posture" in r
    assert "CWE-798" in r  # a control area derived from a finding
    assert "CIS Controls v8" in r and "NIST" in r  # mechanism controls cited
    assert "chain intact" in r  # signed -> "tamper-evident ... HMAC-signed"; keyless -> "SHA-256 linked"
    assert "not a compliance certification" in r.lower()  # the honesty line
    assert "SOC 2" in r  # now asserted via AICPA TSC mechanism controls
    assert "EU AI Act" in r and "ISO/IEC 42001" in r  # AI regimes folded in (official URLs)
    assert "high-risk" in r.lower()  # EU AI Act correctly scoped to high-risk only
    assert "US AI law" in r  # honestly marked out of scope in PENDING


def test_broken_chain_flags_evidence_integrity():
    store, chain = _seeded()
    store._tamper_for_test("acme", 1, '{"x":1}')
    assert "COMPROMISED" in compliance_report(store, chain, "acme")


def test_compliance_is_org_isolated():
    store, chain = _seeded()
    ingest_change(store, chain, "globex", "web", DIRTY, Attribution("b", "human"))
    d = compliance_data(store, chain, "acme")
    assert d["changes"] == 1  # only acme's change counts


def test_control_coverage_and_ssdf_mechanism():
    store, chain = _seeded()
    d = compliance_data(store, chain, "acme")
    assert d["control_coverage"] >= 1
    assert any("SSDF" in mc["framework_name"] or "Secure Software" in mc["framework_name"]
               for mc in d["mechanism_controls"])  # NIST SSDF mechanism control present + cited
    r = compliance_report(store, chain, "acme")
    assert "Control coverage" in r


def test_control_coverage_does_not_double_count_gdpr_id_vs_name():
    # MED: control_coverage must count DISTINCT real frameworks. A GDPR finding cites the
    # grounding id gdpr-art5-art32 while the GDPR mechanism uses the compliance id 'gdpr';
    # before normalization the two GDPR strings counted as two frameworks (unitless union of
    # id-space and name-space). After the fix, a GDPR finding adds NO new distinct framework
    # because GDPR is already covered by an always-on mechanism.
    store = GovernanceStore()
    chain = GovernanceChain(store)
    # A diff whose only finding is PII (a real email) -> framework gdpr-art5-art32.
    pii_diff = (
        "--- a/app/owner.py\n+++ b/app/owner.py\n@@ -1,1 +1,2 @@\n x = 1\n"
        '+owner = "' + "jane.doe@acmecorp.com" + '"\n'
    )
    ingest_change(store, chain, "acme", "api", pii_diff, Attribution("alice", "claude"))
    d = compliance_data(store, chain, "acme")
    # the PII finding's GDPR control area is present...
    assert any("gdpr" in (ca["framework"] or "").lower() for ca in d["control_areas"])
    # ...but GDPR is already a mechanism framework, so coverage = distinct mechanism frameworks
    # (no +1 from the id-vs-name duplicate).
    distinct_mechanism_frameworks = len({mc["framework"] for mc in MECHANISM_CONTROLS})
    assert d["control_coverage"] == distinct_mechanism_frameworks


def test_mechanism_frameworks_are_all_registered():
    # Referential integrity: every framework id a mechanism control cites MUST exist
    # in COMPLIANCE_FRAMEWORKS, else compliance_data() KeyErrors only at render time.
    cited = {mc["framework"] for mc in MECHANISM_CONTROLS}
    assert cited <= set(COMPLIANCE_FRAMEWORKS)


def test_clean_change_report_has_no_control_gaps():
    # A clean change yields zero findings -> the empty control_areas branch.
    store = GovernanceStore()
    chain = GovernanceChain(store)
    ingest_change(store, chain, "acme", "api", CLEAN, Attribution("alice", "claude"))
    d = compliance_data(store, chain, "acme")
    assert d["findings"] == 0
    r = compliance_report(store, chain, "acme")
    assert "no findings (no control gaps surfaced" in r


def test_verified_pending_split_is_code_bound():
    # Binds the regulator brief's verified-vs-pending partition to shipped code:
    # every ASSERTED framework carries a last_verified date, and no PENDING_REGIMES
    # prose string is emitted as an asserted control_area or mechanism control.
    for fw in COMPLIANCE_FRAMEWORKS.values():
        assert fw.get("last_verified")  # nothing asserted without a freshness date
    asserted_text = " ".join(mc["control"] + " " + mc["mechanism"] for mc in MECHANISM_CONTROLS)
    for pending in PENDING_REGIMES:
        assert pending not in asserted_text  # pending prose stays pending, never asserted
