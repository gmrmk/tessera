"""Client-ready evidence report rendering for Tessera Harden."""
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
        current = _sha_file(project / rel)
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
        evidence_gaps.append("No generated policy inventory is present.")
    if verification is None:
        evidence_gaps.append("No adversarial verification receipt is present.")
    elif not verification_current:
        evidence_gaps.append("One or more installed artifacts differ from the hashes exercised by the verification harness.")
    if verification is not None and not manifest_current:
        evidence_gaps.append("The verification receipt does not match the active installation manifest.")
    if severity_counts.get("CRITICAL", 0) or severity_counts.get("HIGH", 0):
        evidence_gaps.append("The current audit contains high-severity configuration findings requiring remediation.")
    unvalidated = status_counts.get("NOT-TECHNICALLY-ENFORCEABLE", 0)
    if unvalidated:
        evidence_gaps.append(
            f"{unvalidated} policy statement(s) remain accountable human judgment rather than deterministic controls."
        )

    return {
        "schema_version": 2,
        "root": ".",
        "project_name": project.name,
        "generated_at": audit["generated_at"],
        "verdict": verdict,
        "summary": {
            "policy_statements_reviewed": len(rules),
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
        "disclaimer": (
            "This report records deterministic configuration analysis and named fixture results. It is not a penetration test, "
            "legal opinion, compliance certification, security attestation, or proof that every unsafe action is impossible."
        ),
    }


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _short_hash(value: Any) -> str:
    return str(value)[:12] if isinstance(value, str) and value else "—"


def render_markdown(data: dict[str, Any]) -> str:
    summary = data["summary"]
    audit = data["audit"]
    verification = data.get("verification")
    lines = [
        "# Tessera Harden Evidence Report",
        "",
        f"**Project:** `{data['project_name']}`  ",
        f"**Generated:** {data['generated_at']}  ",
        f"**Evidence verdict:** **{data['verdict']}**",
        "",
        "## Executive summary",
        "",
        "| Measure | Result |",
        "|---|---:|",
        f"| Policy statements reviewed | **{summary['policy_statements_reviewed']}** |",
        f"| Adversarial cases | **{summary['verification_cases']}** |",
        f"| Passed | **{summary['verification_passed']}** |",
        f"| Failed | **{summary['verification_failed']}** |",
        f"| Verification matches current artifacts | **{'YES' if summary['verification_current'] else 'NO'}** |",
        f"| Verification matches active manifest | **{'YES' if summary['manifest_current'] else 'NO'}** |",
        "",
        "### Enforcement status",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status in _STATUS_ORDER:
        lines.append(f"| {status} | {summary['status_counts'].get(status, 0)} |")

    lines.extend(["", "## Evidence gaps", ""])
    if data["evidence_gaps"]:
        lines.extend(f"- {gap}" for gap in data["evidence_gaps"])
    else:
        lines.append("- No evidence gaps were detected in the generated scope.")

    lines.extend(["", "## Installed-artifact integrity", "", "| Artifact | Verified SHA-256 | Current SHA-256 | Match |", "|---|---|---|---|"])
    if data["artifact_integrity"]:
        for item in data["artifact_integrity"]:
            lines.append(
                f"| `{_md_escape(item['path'])}` | `{_short_hash(item['verified_sha256'])}` | "
                f"`{_short_hash(item['current_sha256'])}` | {'YES' if item['match'] else 'NO'} |"
            )
    else:
        lines.append("| — | — | — | No verification hashes recorded |")

    lines.extend(["", "## Configuration findings", "", "| Severity | Finding | Source | Remediation |", "|---|---|---|---|"])
    findings = audit["findings"]
    if findings:
        for finding in findings:
            lines.append(
                f"| {_md_escape(finding['severity'])} | **{_md_escape(finding['title'])}** — {_md_escape(finding['detail'])} "
                f"| {_md_escape(finding.get('source') or '—')} | {_md_escape(finding.get('remediation') or '—')} |"
            )
    else:
        lines.append("| INFO | No configuration findings in the audited scope. | — | Continue periodic verification. |")

    lines.extend(["", "## Policy-to-control inventory", "", "| Rule | Source | Statement | Status | Control | Hook / decision |", "|---|---|---|---|---|---|"])
    rules = audit["rules"]
    if rules:
        for rule in rules:
            lines.append(
                f"| `{_md_escape(rule['rule_id'])}` | `{_md_escape(rule['source'])}:{rule['line']}` "
                f"| {_md_escape(rule['text'])} | **{_md_escape(rule['status'])}** "
                f"| `{_md_escape(rule.get('control_id') or 'none')}` "
                f"| `{_md_escape(rule.get('hook_event') or 'none')} / {_md_escape(rule.get('decision') or 'none')}` |"
            )
    else:
        lines.append("| — | — | No normative statements extracted. | NOT-TECHNICALLY-ENFORCEABLE | `TESSERA-HUMAN-001` | `none / none` |")

    lines.extend(["", "## Installed controls", ""])
    for control in audit["controls"]:
        lines.extend(
            [
                f"### {control['control_id']} — {control['title']}",
                "",
                f"**Status:** {control['status']}  ",
                f"**Hook:** {control['hook_event']} → `{control['decision']}`",
                "",
                control["description"],
                "",
                f"**Evidence:** {control['evidence']}",
                "",
                "**Known limitations:**",
            ]
        )
        lines.extend(f"- {limitation}" for limitation in control["limitations"])
        lines.append("")

    lines.extend(["## Adversarial verification", ""])
    if not verification:
        lines.append("No verification receipt is present. Run `tessera harden verify --break-each-rule`.")
        lines.append("")
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
        lines.extend(["", "### Verification limitations", ""])
        lines.extend(f"- {limitation}" for limitation in verification.get("limitations", []))
        lines.append("")

    lines.extend(["## Boundary statement", "", data["disclaimer"], ""])
    return "\n".join(lines)


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _badge(value: str) -> str:
    cls = value.lower().replace("-", "_")
    return f'<span class="badge {cls}">{_h(value)}</span>'


def _html_table(headers: list[str], rows: list[list[Any]], *, classes: str = "") -> str:
    head = "".join(f"<th>{_h(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="tablewrap"><table class="{_h(classes)}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(data: dict[str, Any]) -> str:
    summary = data["summary"]
    audit = data["audit"]
    verification = data.get("verification")
    cards = [
        ("Verdict", data["verdict"]),
        ("Policy rules", summary["policy_statements_reviewed"]),
        ("Adversarial cases", summary["verification_cases"]),
        ("Passed", summary["verification_passed"]),
        ("Failed", summary["verification_failed"]),
        ("Artifact match", "Yes" if summary["verification_current"] else "No"),
    ]
    card_html = "".join(
        f'<article class="card"><div class="label">{_h(label)}</div><div class="metric">{_h(value)}</div></article>'
        for label, value in cards
    )

    status_rows = [[_badge(status), str(summary["status_counts"].get(status, 0))] for status in _STATUS_ORDER]
    gaps = "".join(f"<li>{_h(gap)}</li>" for gap in data["evidence_gaps"]) or "<li>No evidence gaps detected in the generated scope.</li>"
    integrity_rows = [
        [
            f"<code>{_h(item['path'])}</code>",
            f"<code>{_h(_short_hash(item['verified_sha256']))}</code>",
            f"<code>{_h(_short_hash(item['current_sha256']))}</code>",
            _badge("MATCH" if item["match"] else "DRIFT"),
        ]
        for item in data["artifact_integrity"]
    ] or [["—", "—", "—", _badge("NOT-VERIFIED")]]
    finding_rows = [
        [
            _badge(finding["severity"]),
            f"<strong>{_h(finding['title'])}</strong><br><span class=\"muted\">{_h(finding['detail'])}</span>",
            _h(finding.get("source") or "—"),
            _h(finding.get("remediation") or "—"),
        ]
        for finding in audit["findings"]
    ] or [[_badge("INFO"), "No configuration findings in the audited scope.", "—", "Continue periodic verification."]]
    rule_rows = [
        [
            f"<code>{_h(rule['rule_id'])}</code>",
            f"<code>{_h(rule['source'])}:{rule['line']}</code>",
            _h(rule["text"]),
            _badge(rule["status"]),
            f"<code>{_h(rule.get('control_id') or 'none')}</code>",
        ]
        for rule in audit["rules"]
    ] or [["—", "—", "No normative statements extracted.", _badge("NOT-TECHNICALLY-ENFORCEABLE"), "<code>TESSERA-HUMAN-001</code>"]]
    control_html = "".join(
        "<article class=\"control\">"
        f"<div class=\"controlhead\"><h3>{_h(control['control_id'])} · {_h(control['title'])}</h3>{_badge(control['status'])}</div>"
        f"<p>{_h(control['description'])}</p>"
        f"<p><strong>Hook:</strong> <code>{_h(control['hook_event'])}</code> → <code>{_h(control['decision'])}</code></p>"
        f"<p><strong>Evidence:</strong> {_h(control['evidence'])}</p>"
        "<details><summary>Known limitations</summary><ul>"
        + "".join(f"<li>{_h(item)}</li>" for item in control["limitations"])
        + "</ul></details></article>"
        for control in audit["controls"]
    )

    if verification:
        verification_rows = [
            [
                f"<code>{_h(result['case_id'])}</code><br><span class=\"muted\">{_h(result['description'])}</span>",
                f"<code>{_h(result['expected_decision'])}</code>",
                f"<code>{_h(result['actual_decision'])}</code>",
                f"<code>{_h(result.get('rule_id') or '—')}</code>",
                _badge("PASS" if result["passed"] else "FAIL"),
            ]
            for result in verification.get("results", [])
        ]
        verification_html = (
            f"<p><strong>Runtime:</strong> <code>{_h((verification.get('runtime') or {}).get('command', 'node'))} "
            f"{_h((verification.get('runtime') or {}).get('version', 'unknown'))}</code> · "
            f"<strong>Manifest:</strong> <code>{_h(verification.get('manifest_id') or 'none')}</code></p>"
            + _html_table(["Case", "Expected", "Actual", "Rule", "Result"], verification_rows)
            + "<h3>Verification limitations</h3><ul>"
            + "".join(f"<li>{_h(item)}</li>" for item in verification.get("limitations", []))
            + "</ul>"
        )
    else:
        verification_html = "<div class=\"notice\">No verification receipt is present. Run <code>tessera harden verify --break-each-rule</code>.</div>"

    css = """
:root{--ink:#172033;--muted:#64748b;--line:#dbe3ef;--panel:#f7f9fc;--accent:#273c75;--good:#176b45;--bad:#9f2d2d;--warn:#8a5a00;--violet:#6541a5}
*{box-sizing:border-box}body{margin:0;background:#eef2f7;color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1240px;margin:32px auto;background:white;border:1px solid var(--line);border-radius:18px;box-shadow:0 18px 55px rgba(23,32,51,.10);overflow:hidden}.hero{padding:42px 48px;background:linear-gradient(135deg,#172033,#273c75);color:white}.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-weight:700;font-size:12px;opacity:.72}.hero h1{font-size:42px;line-height:1.08;margin:.35rem 0}.hero p{max-width:760px;margin:.4rem 0;opacity:.85}.section{padding:30px 48px;border-top:1px solid var(--line)}h2{font-size:25px;margin:0 0 18px}h3{font-size:17px;margin:0}.cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}.card{padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}.label{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:700}.metric{font-size:25px;font-weight:800;margin-top:5px}.grid2{display:grid;grid-template-columns:1fr 1.8fr;gap:24px}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:640px}th{background:var(--panel);text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}th,td{padding:11px 13px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:last-child td{border-bottom:0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;background:#edf1f7;padding:.12rem .32rem;border-radius:5px}.muted{color:var(--muted)}.badge{display:inline-block;padding:.2rem .48rem;border-radius:999px;font-size:11px;font-weight:800;white-space:nowrap;background:#e8edf5;color:#344054}.badge.pass,.badge.match,.badge.enforced,.badge.info{background:#e4f5ec;color:var(--good)}.badge.fail,.badge.drift,.badge.critical,.badge.high{background:#fdeaea;color:var(--bad)}.badge.warn_only,.badge.warn,.badge.medium,.badge.stale{background:#fff2ce;color:var(--warn)}.badge.requires_human_approval,.badge.not_technically_enforceable{background:#eee8fb;color:var(--violet)}.control{border:1px solid var(--line);border-radius:12px;padding:18px;margin:12px 0}.controlhead{display:flex;gap:16px;align-items:center;justify-content:space-between}.control p{margin:.55rem 0}.notice{border-left:4px solid var(--warn);background:#fff8e5;padding:14px 16px;border-radius:6px}footer{padding:24px 48px;background:var(--panel);color:var(--muted);border-top:1px solid var(--line)}@media(max-width:950px){.cards{grid-template-columns:repeat(3,1fr)}.grid2{grid-template-columns:1fr}.hero,.section{padding-left:24px;padding-right:24px}}@media(max-width:560px){.cards{grid-template-columns:repeat(2,1fr)}.hero h1{font-size:32px}}
""".strip()

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Tessera Harden Evidence Report</title><style>" + css + "</style></head><body><main>"
        f"<header class=\"hero\"><div class=\"eyebrow\">Tessera Harden · Evidence, not assurances</div><h1>{_h(data['project_name'])}</h1>"
        f"<p>Generated {_h(data['generated_at'])}. Verdict: {_badge(data['verdict'])}</p></header>"
        f"<section class=\"section\"><div class=\"cards\">{card_html}</div></section>"
        f"<section class=\"section grid2\"><div><h2>Enforcement profile</h2>{_html_table(['Status','Count'],status_rows)}</div><div><h2>Evidence gaps</h2><ul>{gaps}</ul></div></section>"
        f"<section class=\"section\"><h2>Installed-artifact integrity</h2>{_html_table(['Artifact','Verified SHA-256','Current SHA-256','Result'],integrity_rows)}</section>"
        f"<section class=\"section\"><h2>Configuration findings</h2>{_html_table(['Severity','Finding','Source','Remediation'],finding_rows)}</section>"
        f"<section class=\"section\"><h2>Policy-to-control inventory</h2>{_html_table(['Rule','Source','Statement','Status','Control'],rule_rows)}</section>"
        f"<section class=\"section\"><h2>Installed controls</h2>{control_html}</section>"
        f"<section class=\"section\"><h2>Adversarial verification</h2>{verification_html}</section>"
        f"<footer><strong>Boundary statement.</strong> {_h(data['disclaimer'])}</footer>"
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
