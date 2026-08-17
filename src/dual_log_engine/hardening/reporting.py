"""Human-readable evidence report rendering for Tessera Harden."""
from __future__ import annotations

import hashlib
import html
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from .scanner import audit_project, resolve_root

_STATUS_ORDER = (
    "ENFORCED",
    "REQUIRES-HUMAN-APPROVAL",
    "WARN-ONLY",
    "NOT-TECHNICALLY-ENFORCEABLE",
)
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _load_optional_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _sha_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def report_data(root: str | os.PathLike[str]) -> dict[str, Any]:
    project = resolve_root(root)
    audit = audit_project(project).to_dict()
    inventory = _load_optional_json(project / ".tessera" / "governance-inventory.json")
    verification = _load_optional_json(project / ".tessera" / "verification.json")
    manifest = _load_optional_json(project / ".tessera" / "install-manifest.json")
    rules = audit["rules"]
    status_counts = Counter(rule["status"] for rule in rules)
    severity_counts = Counter(finding["severity"] for finding in audit["findings"])

    expected_hashes = (verification or {}).get("artifact_hashes", {})
    if not isinstance(expected_hashes, dict):
        expected_hashes = {}
    hash_checks: list[dict[str, Any]] = []
    for rel, expected in sorted(expected_hashes.items()):
        if not isinstance(rel, str):
            continue
        candidate = (project / rel).resolve()
        current = _sha_file(candidate) if candidate.is_relative_to(project) else None
        hash_checks.append(
            {
                "path": rel,
                "verified_sha256": expected if isinstance(expected, str) else None,
                "current_sha256": current,
                "match": isinstance(expected, str) and current == expected,
            }
        )
    verification_current = bool(hash_checks) and all(item["match"] for item in hash_checks)
    manifest_current = bool(
        verification
        and manifest
        and verification.get("manifest_id")
        and verification.get("manifest_id") == manifest.get("manifest_id")
    )

    blocking_findings = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
    if blocking_findings:
        verdict = "FAIL"
    elif verification is None:
        verdict = "NOT-VERIFIED"
    elif not verification.get("ok"):
        verdict = "FAIL"
    elif not verification_current or not manifest_current:
        verdict = "STALE"
    else:
        verdict = "PASS"

    evidence_gaps: list[str] = []
    if manifest is None:
        evidence_gaps.append("No active installation manifest is present.")
    if inventory is None:
        evidence_gaps.append("No generated requirement inventory is present.")
    if verification is None:
        evidence_gaps.append("No adversarial verification receipt is present.")
    elif not verification_current:
        evidence_gaps.append("One or more installed artifacts differ from the hashes that were verified.")
    if verification is not None and not manifest_current:
        evidence_gaps.append("The verification receipt does not match the active installation manifest.")
    if blocking_findings:
        evidence_gaps.append("The current audit contains high-severity configuration findings.")
    unmapped = status_counts.get("NOT-TECHNICALLY-ENFORCEABLE", 0)
    if unmapped:
        evidence_gaps.append(f"{unmapped} sourced requirement(s) have no deterministic Tessera control mapping.")

    unknown_authority = sum(1 for rule in rules if rule.get("authority_status") == "NOT-SPECIFIED")
    if unknown_authority:
        evidence_gaps.append(
            f"Approval or ownership authority is not specified in analyzed source for {unknown_authority} requirement(s). Tessera did not infer it."
        )

    return {
        "schema_version": 3,
        "root": ".",
        "project_name": project.name,
        "generated_at": audit["generated_at"],
        "verdict": verdict,
        "reporting_invariants": {
            "source_preserving": True,
            "invent_organization_context": False,
            "unknowns_remain_unknown": True,
            "interpretation_must_be_labeled": True,
        },
        "summary": {
            "requirements_reviewed": len(rules),
            "status_counts": {status: status_counts.get(status, 0) for status in _STATUS_ORDER},
            "finding_counts": {severity: severity_counts.get(severity, 0) for severity in _SEVERITY_ORDER},
            "verification_cases": int((verification or {}).get("case_count", 0))
            or int((verification or {}).get("passed", 0)) + int((verification or {}).get("failed", 0)),
            "verification_passed": int((verification or {}).get("passed", 0)),
            "verification_failed": int((verification or {}).get("failed", 0)),
            "verification_ok": (verification or {}).get("ok"),
            "verification_current": verification_current,
            "manifest_current": manifest_current,
        },
        "artifact_integrity": hash_checks,
        "evidence_gaps": evidence_gaps,
        "audit": audit,
        "inventory": inventory,
        "manifest": manifest,
        "verification": verification,
        "boundary": (
            "Tessera reports what was found in analyzed source, what control was mapped, and what was tested. "
            "It does not invent organizational owners, approvers, policy intent, business rationale, or missing facts."
        ),
        "disclaimer": (
            "This report records deterministic configuration analysis and named fixture results. It is not a penetration test, "
            "legal opinion, compliance certification, security attestation, or proof that every unsafe action is impossible."
        ),
    }


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _short_hash(value: Any) -> str:
    return str(value)[:12] if isinstance(value, str) and value else "—"


def _authority(rule: dict[str, Any]) -> str:
    return str(rule.get("authority") or "Not specified in analyzed source")


def _interpretation(rule: dict[str, Any]) -> str:
    status = rule.get("interpretation_status") or "NOT-PERFORMED"
    value = rule.get("interpretation")
    if value:
        return f"{status}: {value}"
    return str(status)


def render_markdown(data: dict[str, Any]) -> str:
    summary = data["summary"]
    audit = data["audit"]
    verification = data.get("verification")
    lines = [
        "# Tessera Harden Evidence Report",
        "",
        f"**Project:** `{data['project_name']}`  ",
        f"**Generated:** {data['generated_at']}  ",
        f"**Verdict:** **{data['verdict']}**",
        "",
        data["boundary"],
        "",
        "## Summary",
        "",
        "| Measure | Result |",
        "|---|---:|",
        f"| Requirements reviewed | **{summary['requirements_reviewed']}** |",
        f"| Verification cases | **{summary['verification_cases']}** |",
        f"| Passed | **{summary['verification_passed']}** |",
        f"| Failed | **{summary['verification_failed']}** |",
        f"| Verified hashes match current artifacts | **{'YES' if summary['verification_current'] else 'NO'}** |",
        f"| Verification matches active manifest | **{'YES' if summary['manifest_current'] else 'NO'}** |",
        "",
        "## Requirements",
        "",
    ]

    if audit["rules"]:
        for rule in audit["rules"]:
            lines.extend(
                [
                    f"### {rule['rule_id']}",
                    "",
                    f"**Requirement:** {_md_escape(rule['text'])}",
                    f"**Source:** `{_md_escape(rule['source'])}:{rule['line']}`",
                    f"**Source type:** {rule.get('source_kind', 'ORGANIZATION')}",
                    f"**Tessera status:** **{rule['status']}**",
                    f"**Mapped control:** `{rule.get('control_id') or 'none'}`",
                    f"**Hook / decision:** `{rule.get('hook_event') or 'none'} / {rule.get('decision') or 'none'}`",
                    f"**Authority:** {_md_escape(_authority(rule))}",
                    f"**Interpretation:** {_md_escape(_interpretation(rule))}",
                    f"**Mapping basis:** {_md_escape(rule.get('rationale') or 'No mapping basis recorded.')}",
                    "",
                ]
            )
    else:
        lines.extend(["No normative requirements were extracted from the analyzed source files.", ""])

    lines.extend(["## Evidence gaps", ""])
    if data["evidence_gaps"]:
        lines.extend(f"- {gap}" for gap in data["evidence_gaps"])
    else:
        lines.append("- None detected in the generated scope.")

    lines.extend(["", "## Configuration findings", "", "| Severity | Finding | Source | Suggested action |", "|---|---|---|---|"])
    findings = audit["findings"]
    if findings:
        for finding in findings:
            lines.append(
                f"| {_md_escape(finding['severity'])} | **{_md_escape(finding['title'])}** — {_md_escape(finding['detail'])} "
                f"| {_md_escape(finding.get('source') or '—')} | {_md_escape(finding.get('remediation') or '—')} |"
            )
    else:
        lines.append("| INFO | No configuration findings in the audited scope. | — | — |")

    lines.extend(["", "## Installed controls", ""])
    for control in audit["controls"]:
        lines.extend(
            [
                f"### {control['control_id']} — {control['title']}",
                "",
                f"**Status:** {control['status']}  ",
                f"**Hook:** {control['hook_event']} → `{control['decision']}`",
                "",
                f"**What Tessera does:** {control['description']}",
                "",
                f"**Evidence available:** {control['evidence']}",
                "",
                "**Limits:**",
            ]
        )
        lines.extend(f"- {limitation}" for limitation in control["limitations"])
        lines.append("")

    lines.extend(["## Installed artifact integrity", "", "| Artifact | Verified SHA-256 | Current SHA-256 | Match |", "|---|---|---|---|"])
    if data["artifact_integrity"]:
        for item in data["artifact_integrity"]:
            lines.append(
                f"| `{_md_escape(item['path'])}` | `{_short_hash(item['verified_sha256'])}` | "
                f"`{_short_hash(item['current_sha256'])}` | {'YES' if item['match'] else 'NO'} |"
            )
    else:
        lines.append("| — | — | — | No verification hashes recorded |")

    lines.extend(["", "## Adversarial verification", ""])
    if not verification:
        lines.extend(["No verification receipt is present.", ""])
    else:
        runtime = verification.get("runtime", {})
        lines.extend(
            [
                f"**Runtime:** `{_md_escape(runtime.get('command', 'node'))} {_md_escape(runtime.get('version', 'unknown'))}`  ",
                f"**Manifest:** `{_md_escape(verification.get('manifest_id') or 'none')}`  ",
                f"**Generated:** {verification.get('generated_at', 'unknown')}",
                "",
                "| Case | Expected | Actual | Rule | Result |",
                "|---|---|---|---|---|",
            ]
        )
        for result in verification.get("results", []):
            lines.append(
                f"| `{_md_escape(result['case_id'])}` — {_md_escape(result['description'])} "
                f"| `{_md_escape(result['expected_decision'])}` | `{_md_escape(result['actual_decision'])}` "
                f"| `{_md_escape(result.get('rule_id') or '—')}` | {'PASS' if result['passed'] else 'FAIL'} |"
            )
        lines.extend(["", "### Verification limits", ""])
        lines.extend(f"- {limitation}" for limitation in verification.get("limitations", []))
        lines.append("")

    lines.extend(["## Boundary", "", data["disclaimer"], ""])
    return "\n".join(lines)


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _badge(value: str) -> str:
    cls = value.lower().replace("-", "_")
    return f'<span class="badge {cls}">{_h(value)}</span>'


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_h(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(data: dict[str, Any]) -> str:
    summary = data["summary"]
    audit = data["audit"]
    verification = data.get("verification")

    requirement_cards = []
    for rule in audit["rules"]:
        requirement_cards.append(
            "<article class=\"requirement\">"
            f"<div class=\"reqhead\"><code>{_h(rule['rule_id'])}</code>{_badge(rule['status'])}</div>"
            f"<h3>{_h(rule['text'])}</h3>"
            f"<dl><dt>Source</dt><dd><code>{_h(rule['source'])}:{rule['line']}</code></dd>"
            f"<dt>Mapped control</dt><dd><code>{_h(rule.get('control_id') or 'none')}</code></dd>"
            f"<dt>Hook / decision</dt><dd><code>{_h(rule.get('hook_event') or 'none')} / {_h(rule.get('decision') or 'none')}</code></dd>"
            f"<dt>Authority</dt><dd>{_h(_authority(rule))}</dd>"
            f"<dt>Interpretation</dt><dd>{_h(_interpretation(rule))}</dd>"
            f"<dt>Mapping basis</dt><dd>{_h(rule.get('rationale') or 'No mapping basis recorded.')}</dd></dl>"
            "</article>"
        )
    requirements_html = "".join(requirement_cards) or "<p>No normative requirements were extracted from analyzed source.</p>"

    gaps = "".join(f"<li>{_h(gap)}</li>" for gap in data["evidence_gaps"]) or "<li>None detected in the generated scope.</li>"
    integrity_rows = [
        [f"<code>{_h(i['path'])}</code>", f"<code>{_h(_short_hash(i['verified_sha256']))}</code>", f"<code>{_h(_short_hash(i['current_sha256']))}</code>", _badge("MATCH" if i["match"] else "DRIFT")]
        for i in data["artifact_integrity"]
    ] or [["—", "—", "—", _badge("NOT-VERIFIED")]]
    finding_rows = [
        [_badge(f["severity"]), f"<strong>{_h(f['title'])}</strong><br><span class=\"muted\">{_h(f['detail'])}</span>", _h(f.get("source") or "—"), _h(f.get("remediation") or "—")]
        for f in audit["findings"]
    ] or [[_badge("INFO"), "No configuration findings in the audited scope.", "—", "—"]]

    control_html = "".join(
        "<article class=\"control\">"
        f"<div class=\"reqhead\"><h3>{_h(c['control_id'])} — {_h(c['title'])}</h3>{_badge(c['status'])}</div>"
        f"<p><strong>What Tessera does:</strong> {_h(c['description'])}</p>"
        f"<p><strong>Hook:</strong> <code>{_h(c['hook_event'])}</code> → <code>{_h(c['decision'])}</code></p>"
        f"<p><strong>Evidence available:</strong> {_h(c['evidence'])}</p>"
        "<details><summary>Limits</summary><ul>" + "".join(f"<li>{_h(x)}</li>" for x in c["limitations"]) + "</ul></details></article>"
        for c in audit["controls"]
    )

    if verification:
        verification_rows = [
            [f"<code>{_h(r['case_id'])}</code><br><span class=\"muted\">{_h(r['description'])}</span>", f"<code>{_h(r['expected_decision'])}</code>", f"<code>{_h(r['actual_decision'])}</code>", f"<code>{_h(r.get('rule_id') or '—')}</code>", _badge("PASS" if r["passed"] else "FAIL")]
            for r in verification.get("results", [])
        ]
        verification_html = _html_table(["Case", "Expected", "Actual", "Rule", "Result"], verification_rows)
    else:
        verification_html = "<p>No verification receipt is present.</p>"

    css = """
:root{--ink:#1d2430;--muted:#667085;--line:#d9dee7;--panel:#f7f8fa;--good:#176b45;--bad:#9f2d2d;--warn:#805400;--violet:#6541a5}
*{box-sizing:border-box}body{margin:0;background:#f1f3f6;color:var(--ink);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1120px;margin:28px auto;background:#fff;border:1px solid var(--line)}header,.section,footer{padding:28px 36px}header{border-bottom:1px solid var(--line)}header h1{margin:0 0 6px;font-size:30px}header p{margin:5px 0;color:var(--muted)}.section{border-bottom:1px solid var(--line)}h2{margin:0 0 16px;font-size:22px}h3{margin:0;font-size:16px}.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.metric{border:1px solid var(--line);padding:13px;background:var(--panel)}.metric b{display:block;font-size:22px}.metric span{font-size:12px;color:var(--muted)}.requirement,.control{border:1px solid var(--line);padding:16px;margin:12px 0}.reqhead{display:flex;justify-content:space-between;gap:12px;align-items:center}.requirement h3{margin:12px 0;font-weight:600}.requirement dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;margin:0}.requirement dt{color:var(--muted)}.requirement dd{margin:0}.tablewrap{overflow:auto;border:1px solid var(--line)}table{width:100%;border-collapse:collapse;min-width:650px}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--panel);font-size:12px;color:var(--muted)}.badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;font-weight:700;background:#e8ebf0}.badge.pass,.badge.match,.badge.enforced,.badge.info{background:#e4f5ec;color:var(--good)}.badge.fail,.badge.drift,.badge.critical,.badge.high{background:#fdeaea;color:var(--bad)}.badge.warn_only,.badge.warn,.badge.medium,.badge.stale{background:#fff2ce;color:var(--warn)}.badge.requires_human_approval,.badge.not_technically_enforceable{background:#eee8fb;color:var(--violet)}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f0f2f5;padding:1px 4px}.muted,footer{color:var(--muted)}@media(max-width:760px){main{margin:0}.summary{grid-template-columns:repeat(2,1fr)}header,.section,footer{padding:20px}.requirement dl{grid-template-columns:1fr}}
""".strip()

    metrics = "".join(
        f'<div class="metric"><b>{_h(value)}</b><span>{_h(label)}</span></div>'
        for label, value in [
            ("Verdict", data["verdict"]),
            ("Requirements", summary["requirements_reviewed"]),
            ("Verification cases", summary["verification_cases"]),
            ("Passed", summary["verification_passed"]),
            ("Failed", summary["verification_failed"]),
        ]
    )

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Tessera Harden Evidence Report</title><style>" + css + "</style></head><body><main>"
        f"<header><h1>Tessera Harden Evidence Report</h1><p><strong>Project:</strong> {_h(data['project_name'])} · <strong>Generated:</strong> {_h(data['generated_at'])}</p><p>{_h(data['boundary'])}</p></header>"
        f"<section class=\"section\"><div class=\"summary\">{metrics}</div></section>"
        f"<section class=\"section\"><h2>Requirements</h2>{requirements_html}</section>"
        f"<section class=\"section\"><h2>Evidence gaps</h2><ul>{gaps}</ul></section>"
        f"<section class=\"section\"><h2>Configuration findings</h2>{_html_table(['Severity','Finding','Source','Suggested action'],finding_rows)}</section>"
        f"<section class=\"section\"><h2>Installed controls</h2>{control_html}</section>"
        f"<section class=\"section\"><h2>Installed artifact integrity</h2>{_html_table(['Artifact','Verified SHA-256','Current SHA-256','Result'],integrity_rows)}</section>"
        f"<section class=\"section\"><h2>Adversarial verification</h2>{verification_html}</section>"
        f"<footer>{_h(data['disclaimer'])}</footer>"
        "</main></body></html>\n"
    )


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_report(root: str | os.PathLike[str], format: str = "markdown") -> str:
    data = report_data(root)
    if format == "markdown":
        return render_markdown(data)
    if format == "html":
        return render_html(data)
    if format == "json":
        return render_json(data)
    raise ValueError(f"unsupported report format: {format}")
