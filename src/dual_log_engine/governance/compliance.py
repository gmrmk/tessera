"""Compliance - map the org's governance posture to cited control families.

Honesty discipline (mirrors trust-but-verify): ship ONLY mappings backed by a
verified authoritative citation. Safety findings map to the frameworks their
checks already cite (OWASP / CWE / GDPR - see grounding.py). The governance
MECHANISMS (tamper-evident chain, per-change attribution, continuous scanning,
secret redaction, integrity-checked backup) map to cited controls across CIS v8,
NIST CSF/SSDF/AI-RMF, SOC 2 (AICPA TSC), FDA 21 CFR Part 11, ISO 27001, ISO 42001,
GDPR, and the EU AI Act (scoped: binds only IF the governed system is high-risk).
Most URLs are official primary sources; the two ISO catalog ids (27001 / 42001) are
cross-checked against independent sources because iso.org returns HTTP 403 to automated
fetch (see the per-entry provenance note). All re-verified on the freshness cadence.
Only genuinely org-level controls, out-of-scope regimes (US AI law), and the
append-only-vs-erasure tension stay in PENDING_REGIMES - asserted nowhere without
a verified clause.

ASCII source (no BOM / mojibake), so it passes the repo's pre-commit guard.
"""
from __future__ import annotations

from collections import Counter

from .chain import GovernanceChain
from .store import GovernanceStore

# Compliance-framework citations. Provenance (re-verified 2026-06-29 by a citation agent):
#   primary-confirmed - GDPR + EU AI Act regulation identity (EUR-Lex), SOC 2 TSC
#     (aicpa-cima.com), FDA Part 11 (eCFR official API), CIS Control 8 (cisecurity.org), NIST.
#   cross-checked, NOT primary (iso.org returns HTTP 403 to automated fetch) - the two ISO
#     catalog ids 82875 (27001:2022) + 81230 (42001:2023), each corroborated by 2+ independent
#     sources; open them in a real browser if you need primary confirmation.
#   EU AI Act article->topic mapping (Art 12 record-keeping; Art 19 + 26(6) >=6mo retention)
#     confirmed against the artificialintelligenceact.eu consolidated text.
# Freshness gate: safety/grounding.py verify-grounding.
COMPLIANCE_FRAMEWORKS = {
    "cis-v8-8": {"name": "CIS Controls v8 - Control 8: Audit Log Management", "url": "https://www.cisecurity.org/controls/v8", "last_verified": "2026-06-29"},
    "nist-csf-2": {"name": "NIST Cybersecurity Framework 2.0 (Detect / Identify)", "url": "https://www.nist.gov/cyberframework", "last_verified": "2026-06-29"},
    "nist-ssdf": {"name": "NIST Secure Software Development Framework (SP 800-218)", "url": "https://csrc.nist.gov/Projects/ssdf", "last_verified": "2026-06-29"},
    "soc2-tsc": {"name": "SOC 2 / AICPA Trust Services Criteria (TSP 100) - CC7.1, CC1.5/CC6.1, CC8.1", "url": "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022", "last_verified": "2026-06-29"},
    "fda-part11": {"name": "FDA 21 CFR Part 11.10(e) - secure, time-stamped, append-only audit trail", "url": "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-B/section-11.10", "last_verified": "2026-06-29"},
    "iso-27001": {"name": "ISO/IEC 27001:2022 - A.8.15 Logging, A.5.28 Evidence", "url": "https://www.iso.org/standard/82875.html", "last_verified": "2026-06-29"},
    "gdpr": {"name": "GDPR (EU 2016/679) - Art. 5(2) accountability, Art. 32(1)(b) integrity", "url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj", "last_verified": "2026-06-29"},
    "eu-ai-act": {"name": "EU AI Act (Reg (EU) 2024/1689) - Art. 12 record-keeping, Art. 19/26(6) log retention >=6mo [HIGH-RISK only]", "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj", "last_verified": "2026-06-29"},
    "iso-42001": {"name": "ISO/IEC 42001:2023 - A.6.2.8 AI event-log recording", "url": "https://www.iso.org/standard/81230.html", "last_verified": "2026-06-29"},
    "nist-ai-rmf": {"name": "NIST AI RMF (AI 100-1) + GenAI Profile (AI 600-1) - GV-6.1-008 records of changes, MEASURE 2.7", "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf", "last_verified": "2026-06-29"},
}

# Each governance mechanism -> the controls it evidences, across the verified regimes.
# EU AI Act entries are scoped: they bind only IF the governed system is high-risk.
MECHANISM_CONTROLS = [
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "Audit Log Management - tamper-evident (keyed) / tamper-detecting (keyless), attributable, append-only logs of ingested events", "framework": "cis-v8-8", "evidence": "chain integrity (verify-chain)"},
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "11.10(e) secure, computer-generated, time-stamped audit trail; changes do not obscure prior records", "framework": "fda-part11", "evidence": "keyed verify() detects a forged or truncated tail (keyless mode: accidental edits only)"},
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "A.8.15 Logging (cryptographic hashing / append-only) + A.5.28 evidence unaltered (complete only w.r.t. ingested events; un-ingested changes are outside the chain's threat model)", "framework": "iso-27001", "evidence": "SHA-256 hash chain"},
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "CC7.1 change-detection / integrity of the record", "framework": "soc2-tsc", "evidence": "chain head + verify()"},
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "Art. 12 record-keeping - automatic event logging over the system lifetime [high-risk only]", "framework": "eu-ai-act", "evidence": "append-only auto-recording of every change event"},
    {"mechanism": "Audit chain - HMAC-signed + anchored when DLE_CHAIN_KEY is set (SHA-256 linked append-only otherwise)", "control": "A.6.2.8 AI system recording of event logs", "framework": "iso-42001", "evidence": "append-only AI-change event log"},
    {"mechanism": "Per-change attribution (which agent or human)", "control": "Accountability - attribution recorded per change (self-reported author/agent, not a signed identity)", "framework": "cis-v8-8", "evidence": "every change records author + agent"},
    {"mechanism": "Per-change attribution (which agent or human)", "control": "CC1.5 / CC6.1 accountability - identification extends to software actors (AI agents)", "framework": "soc2-tsc", "evidence": "agent-vs-human recorded per change"},
    {"mechanism": "Per-change attribution (which agent or human)", "control": "Art. 5(2) accountability - demonstrate compliance, not merely comply", "framework": "gdpr", "evidence": "attributable, tamper-evident change record"},
    {"mechanism": "Per-change attribution (which agent or human)", "control": "GV-6.1-008 maintain records of changes (sources, timestamps, metadata)", "framework": "nist-ai-rmf", "evidence": "author + agent + ts per change in the chain"},
    {"mechanism": "Continuous grounded safety scanning of every change", "control": "Detect (continuous monitoring) + Identify (risk visibility)", "framework": "nist-csf-2", "evidence": "findings + dashboard"},
    {"mechanism": "Continuous grounded safety scanning of every change", "control": "Art. 32(1)(d) regular testing/assessing of the effectiveness of measures", "framework": "gdpr", "evidence": "standing, repeating scan of every change"},
    {"mechanism": "Continuous grounded safety scanning of every change", "control": "A.8.28 secure coding + A.8.29 security testing in development", "framework": "iso-27001", "evidence": "every change scanned for vuln classes"},
    {"mechanism": "Continuous grounded safety scanning of every change", "control": "MEASURE 2.7 security and resilience evaluated and documented", "framework": "nist-ai-rmf", "evidence": "documented findings per change"},
    {"mechanism": "Every check tied to a current authoritative framework (no source, no finding)", "control": "Secure-development practices - automated, framework-grounded review", "framework": "nist-ssdf", "evidence": "every finding cites an authoritative source (OWASP/CWE/GDPR/...)"},
    {"mechanism": "Secret redaction before storage", "control": "Art. 32(1)(b) confidentiality + Art. 25 data-minimisation-by-design", "framework": "gdpr", "evidence": "secrets masked before they reach the store"},
    {"mechanism": "Secret redaction before storage", "control": "11.10(c) protection of records (secrets are best-effort redacted before storage)", "framework": "fda-part11", "evidence": "tokens/assignments redacted pre-store"},
    {"mechanism": "Integrity-checked backup + restore (re-verifies the chain) + append-only retention", "control": "Art. 19 / 26(6) keep automatically generated logs >= 6 months [high-risk only]", "framework": "eu-ai-act", "evidence": "durable, restorable, chain-re-verified trail enabling >=6mo retention if operated accordingly (duration not enforced here)"},
    {"mechanism": "Integrity-checked backup + restore (re-verifies the chain) + append-only retention", "control": "Art. 32(1)(c) ability to restore availability + access to data after an incident", "framework": "gdpr", "evidence": "restore re-runs verify() to prove integrity survived"},
    {"mechanism": "Integrity-checked backup + restore (re-verifies the chain) + append-only retention", "control": "11.10(c) accurate, ready retrieval through the retention period", "framework": "fda-part11", "evidence": "SHA-checked snapshot + manifest"},
]

# What is still NOT asserted - and WHY (org-level controls, out-of-scope regimes, known tensions).
PENDING_REGIMES = (
    "EU AI Act: binds only IF the governed system is high-risk (Annex III). Art. 9 risk-management PROCESS, Art. 11 full Annex IV technical documentation, and conformity assessment are org-level - the chain evidences the record-keeping parts (Art. 12/19/26(6)), not the management system. Applies from 2 Aug 2026 for high-risk obligations (verify the staggered Art. 113 schedule against EUR-Lex; not gate-enforced here).",
    "FDA 21 CFR Part 11: electronic SIGNATURES (11.50/11.70/11.200), access/authority controls (11.10(d)/(g)), and a CSV / IQ-OQ-PQ validation package are out of scope for an attribution/audit layer.",
    "SOC 2: the pre-deployment approval workflow (CC8.1) and entity-wide risk assessment (CC3.x) are org controls the product feeds, not implements; SOC 2 sets no fixed retention period (entity-defined).",
    "ISO/IEC 27001 + 42001: the management-system clauses (named role owners, AI impact assessment, a retention schedule with verified deletion) are organizational.",
    "US AI law: NOT in scope - Colorado SB 24-205 was repealed before taking effect (replaced by SB 26-189, eff. 2027); NYC LL144 is employment-AEDT-only; federal EO 14110 was rescinded (EO 14179 removes obligations). No AI-SPECIFIC record-keeping mandate identified for AI-assisted dev tooling (sectoral regimes e.g. HIPAA/SOX/GLBA are deployment-specific and out of scope).",
    "Retention DELETION / right-to-erasure: the append-only design is in tension with GDPR Art. 5(1)(e) / ISO A.8.10 timed erasure - needs a crypto-shredding / tombstoning design (backup + restore shipped; timed erasure not yet).",
)


# Regimes that can be cited on BOTH sides of the coverage union - as a safety-finding
# framework (grounding NAME) and as a governance mechanism (compliance ID) - mapped to one
# canonical token so they are counted once. GDPR is the sole real overlap today (the grounding
# 'gdpr-art5-art32' finding framework vs the 'gdpr' mechanism id); CWE/OWASP have no mechanism
# twin and CIS/NIST/SOC2/ISO/FDA/EU-AI-Act appear only as mechanisms, so each stays distinct.
_CROSS_NAMESPACE_REGIME = "gdpr"


def _canonical_framework(framework: str) -> str:
    """Collapse a framework cited on both the findings side (a name) and the mechanism side
    (an id) to one token, so control_coverage counts distinct REAL frameworks, not id-vs-name
    duplicates. Unrecognized frameworks key on their own string (distinctness preserved)."""
    if _CROSS_NAMESPACE_REGIME in (framework or "").lower():
        return _CROSS_NAMESPACE_REGIME
    return framework


def compliance_data(store: GovernanceStore, chain: GovernanceChain, org: str) -> dict:
    findings = store.findings(org)
    changes = store.changes(org)
    by_fw: Counter = Counter()
    fw_url: dict[str, str] = {}
    for f in findings:
        fw = f.get("framework") or "(ungrounded)"
        by_fw[fw] += 1
        fw_url[fw] = f.get("framework_url") or ""
    control_areas = [
        {"framework": fw, "url": fw_url.get(fw, ""), "findings": n}
        for fw, n in by_fw.most_common()
    ]
    mechanism_controls = [
        {**mc,
         "framework_name": COMPLIANCE_FRAMEWORKS[mc["framework"]]["name"],
         "framework_url": COMPLIANCE_FRAMEWORKS[mc["framework"]]["url"]}
        for mc in MECHANISM_CONTROLS
    ]
    # distinct cited control areas the posture touches (findings + always-on mechanisms).
    # Normalize both sides to ONE key first: control_areas carry the finding's framework NAME
    # while mechanisms carry a compliance framework ID, two namespaces that never collide as
    # strings - so a regime cited on BOTH sides (e.g. GDPR, as the grounding finding framework
    # AND a mechanism) would be double-counted. _canonical_framework maps each side to a shared
    # regime token so the count is distinct REAL frameworks, not a unitless id-plus-name union.
    covered = (
        {_canonical_framework(ca["framework"]) for ca in control_areas}
        | {_canonical_framework(mc["framework"]) for mc in mechanism_controls}
    )
    return {
        "org": org,
        "changes": len(changes),
        "findings": len(findings),
        "control_areas": control_areas,
        "mechanism_controls": mechanism_controls,
        "control_coverage": len(covered),
        "chain": chain.verify(org),
        "pending_regimes": list(PENDING_REGIMES),
    }


def compliance_report(store: GovernanceStore, chain: GovernanceChain, org: str) -> str:
    d = compliance_data(store, chain, org)
    lines = [
        f"# Compliance posture - org: {d['org']}",
        "",
        "> Mappings below are backed by authoritative citations (two ISO ids cross-checked, not primary - iso.org blocks automated fetch). Broader",
        "> regulatory mappings (see 'Pending') require the verified control catalog and are",
        "> NOT asserted here. This is governance evidence, not a compliance certification.",
        "",
        f"Scope: {d['changes']} change(s), {d['findings']} finding(s). "
        f"Control coverage: {d['control_coverage']} distinct cited control area(s).",
        "",
        "## Control areas evidenced by safety findings",
    ]
    if d["control_areas"]:
        for ca in d["control_areas"]:
            lines.append(f"- {ca['framework']}: {ca['findings']} finding(s)  [{ca['url']}]")
    else:
        lines.append("- no findings (no control gaps surfaced by the current checks)")

    lines += ["", "## Governance mechanism controls (always-on evidence)"]
    for mc in d["mechanism_controls"]:
        lines.append(f"- {mc['control']}")
        lines.append(f"    mechanism: {mc['mechanism']}")
        lines.append(f"    evidence:  {mc['evidence']}")
        lines.append(f"    framework: {mc['framework_name']} [{mc['framework_url']}]")

    lines += ["", "## Audit-trail integrity (the evidence's own integrity)"]
    if d["chain"]["ok"]:
        if d["chain"].get("signed"):
            lines.append(f"- [OK] tamper-evident chain intact, HMAC-signed ({d['chain']['entries']} entries) "
                         "- a key-less rewrite would fail verification")
        else:
            lines.append(f"- [OK] chain intact, SHA-256 linked ({d['chain']['entries']} entries) "
                         "- set DLE_CHAIN_KEY for tamper-evidence vs a forger (keyless detects accidental edits)")
    else:
        lines.append(f"- [BROKEN] chain broken at entry {d['chain']['broken_at']}: {d['chain']['reason']} "
                     "- evidence integrity COMPROMISED")

    lines += ["", "## Pending (need the verified control catalog)"]
    for r in d["pending_regimes"]:
        lines.append(f"- {r} - clause-level mapping available once the cited catalog is loaded")
    return "\n".join(lines)
