"""Report - the org read. "What are your people making, and what's risky?"

Rolls up the recorded changes (by agent) and findings (by severity), plus the
tamper-evidence status of the chain. Opens with a coverage-honesty line - absence
of a finding is not proof of safety - mirroring trust-but-verify's anti-survivorship
discipline.

ASCII-only on purpose: a governance/compliance artifact must render identically on
any console or in any file, with no encoding surprises (a Windows cp1252 console
cannot encode emoji or typographic punctuation).
"""
from __future__ import annotations

from .chain import GovernanceChain
from .store import GovernanceStore

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def org_summary(store: GovernanceStore, chain: GovernanceChain, org: str) -> dict:
    changes = store.changes(org)
    findings = store.findings(org)
    by_agent: dict[str, int] = {}
    for c in changes:
        a = c["agent"] or "unknown"
        by_agent[a] = by_agent.get(a, 0) + 1
    return {
        "org": org,
        "changes": len(changes),
        "repos": sorted({c["repo"] for c in changes}),
        "by_agent": by_agent,
        "severity_counts": store.severity_counts(org),
        "findings": findings,
        "chain": chain.verify(org),
    }


def org_report(store: GovernanceStore, chain: GovernanceChain, org: str) -> str:
    s = org_summary(store, chain, org)
    sev = s["severity_counts"]
    lines = [
        f"# Agent-governance report - org: {org}",
        "",
        "> Absence of a finding is not proof of safety - only the checks in the registry ran "
        "(coverage honesty, mirroring trust-but-verify).",
        "",
        "## What your people are making",
        f"- {s['changes']} change(s) across {len(s['repos'])} repo(s): {', '.join(s['repos']) or '(none)'}",
    ]
    for agent, n in sorted(s["by_agent"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  - {agent}: {n} change(s)")

    lines += ["", "## Safety findings"]
    if not s["findings"]:
        lines.append("- none surfaced by the current checks")
    else:
        for level in _SEVERITY_ORDER:
            if sev.get(level):
                lines.append(f"- {level}: {sev[level]}")
        lines += ["", "### Detail"]
        if len(s["findings"]) > 50:
            lines.append(f"(showing first 50 of {len(s['findings'])})")
        for f in s["findings"][:50]:
            lines.append(
                f"- [{f['severity']}] {f['check_id']} | {f['file']}:{f['line']} "
                f"| {f['framework']} | `{f['snippet']}`")

    lines += ["", "## Audit-trail integrity"]
    chk = s["chain"]
    if chk["ok"]:
        if chk.get("signed"):
            lines.append(f"- [OK] tamper-evident chain intact, HMAC-signed ({chk['entries']} entries) "
                         "- a key-less rewrite would fail verification")
            lines.append("- Limit: a full rollback that restores BOTH chain and anchor to a "
                         "consistent earlier state needs an external witness to detect "
                         "(documented in chain.py); not stronger than the dashboard.")
        else:
            lines.append(f"- [OK] chain intact, SHA-256 linked ({chk['entries']} entries) "
                         "- detects accidental edits; set DLE_CHAIN_KEY for tamper-evidence vs a forger")
    else:
        lines.append(
            f"- [BROKEN] chain broken at entry {chk['broken_at']}: {chk['reason']} "
            "- the record may have been altered")
    return "\n".join(lines)
