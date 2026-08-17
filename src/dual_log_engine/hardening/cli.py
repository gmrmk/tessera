"""CLI integration for ``tessera harden``."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .installer import apply_project, rollback_project
from .reporting import render_report
from .scanner import audit_project
from .verification import verify_project


def _write_or_print(text: str, out: str | None) -> None:
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {len(text.encode('utf-8'))} bytes to {path}")
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def _cmd_audit(args: argparse.Namespace) -> int:
    data = audit_project(args.root).to_dict()
    if args.json:
        text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        lines = [
            f"Tessera Harden audit: {data['root']}",
            f"inputs={len(data['inputs'])} rules={len(data['rules'])} findings={len(data['findings'])}",
        ]
        for finding in data["findings"]:
            lines.append(f"[{finding['severity']}] {finding['finding_id']} — {finding['title']}")
            lines.append(f"  {finding['detail']}")
        text = "\n".join(lines) + "\n"
    _write_or_print(text, args.out)
    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    data = audit_project(args.root).to_dict()
    plan = {
        "schema_version": 2,
        "root": data["root"],
        "generated_at": data["generated_at"],
        "rules": data["rules"],
        "controls": data["controls"],
        "files": [
            ".claude/hooks/tessera_guard.mjs",
            ".claude/tessera-policy.json",
            ".claude/settings.json",
            ".tessera/.gitignore",
            ".tessera/governance-inventory.json",
            ".tessera/rule-to-hook-map.md",
        ],
        "runtime": "node",
        "events": ["PreToolUse", "PostToolUse", "Stop", "SessionStart", "ConfigChange"],
        "default_mode": "dry-run",
        "next_command": "tessera harden apply --write",
    }
    if args.json:
        text = json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        lines = [
            f"Tessera Harden plan: {plan['root']}",
            f"policy statements: {len(plan['rules'])}",
            "",
            "Controls:",
        ]
        for control in plan["controls"]:
            lines.append(
                f"- {control['control_id']}: {control['status']} ({control['hook_event']} -> {control['decision']})"
            )
        lines.extend(["", "Generated/merged files:"])
        lines.extend(f"- {path}" for path in plan["files"])
        lines.extend(["", "No files were changed. Apply with: tessera harden apply --write", ""])
        text = "\n".join(lines)
    _write_or_print(text, args.out)
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    result = apply_project(args.root, write=args.write).to_dict()
    if args.json:
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        mode = "APPLIED" if args.write else "DRY RUN"
        lines = [f"Tessera Harden apply — {mode}: {result['root']}"]
        for action in result["actions"]:
            lines.append(f"- {action['action']}: {action['path']}")
        if not args.write:
            lines.append("No files were changed. Re-run with --write after reviewing this plan.")
        elif result.get("manifest_path"):
            lines.append(f"Rollback manifest: {result['manifest_path']}")
        text = "\n".join(lines) + "\n"
    _write_or_print(text, args.out)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    # Verification always exercises every named fixture; the flag makes that intent explicit.
    result = verify_project(args.root, write_receipt=not args.no_write_receipt)
    if args.json:
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        lines = [
            f"Tessera Harden verification: {result['root']}",
            f"runtime={result['runtime']['command']} {result['runtime']['version']}",
            f"cases={result['case_count']} passed={result['passed']} failed={result['failed']}",
        ]
        for case in result["results"]:
            lines.append(
                f"- {'PASS' if case['passed'] else 'FAIL'} {case['case_id']}: expected={case['expected_decision']} actual={case['actual_decision']}"
            )
        text = "\n".join(lines) + "\n"
    _write_or_print(text, args.out)
    return 0 if result["ok"] else 1


def _cmd_report(args: argparse.Namespace) -> int:
    text = render_report(args.root, args.format)
    _write_or_print(text, args.out)
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    result = rollback_project(
        args.root,
        manifest_path=args.manifest,
        write=args.write,
        force=args.force,
    )
    if args.json:
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        mode = "APPLIED" if args.write else "DRY RUN"
        lines = [f"Tessera Harden rollback — {mode}: {result['root']}"]
        for action in result["actions"]:
            lines.append(f"- {action['action']}: {action['path']} ({action['status']})")
        if result["conflicts"]:
            lines.append(f"Conflicts: {result['conflicts']} (use --force only after reviewing current changes)")
        elif not args.write:
            lines.append("No files were changed. Re-run with --write to perform this rollback.")
        text = "\n".join(lines) + "\n"
    _write_or_print(text, args.out)
    return 0 if result["ok"] else 1


def configure_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="harden_cmd", required=True)

    pa = sub.add_parser("audit", help="inspect Claude policy, hooks, settings, and MCP authority")
    pa.add_argument("root", nargs="?", default=".")
    pa.add_argument("--json", action="store_true")
    pa.add_argument("--out", default=None)
    pa.set_defaults(func=_cmd_audit)

    pp = sub.add_parser("plan", help="map policy statements to honest enforcement statuses")
    pp.add_argument("root", nargs="?", default=".")
    pp.add_argument("--json", action="store_true")
    pp.add_argument("--out", default=None)
    pp.set_defaults(func=_cmd_plan)

    pap = sub.add_parser("apply", help="generate project hooks and settings (dry-run by default)")
    pap.add_argument("root", nargs="?", default=".")
    pap.add_argument("--write", action="store_true", help="write files after showing the default dry-run plan")
    pap.add_argument("--json", action="store_true")
    pap.add_argument("--out", default=None)
    pap.set_defaults(func=_cmd_apply)

    pv = sub.add_parser("verify", help="deliberately attempt to break every installed baseline control")
    pv.add_argument("root", nargs="?", default=".")
    pv.add_argument(
        "--break-each-rule",
        action="store_true",
        help="explicitly run the complete adversarial fixture suite (the default behavior)",
    )
    pv.add_argument("--no-write-receipt", action="store_true")
    pv.add_argument("--json", action="store_true")
    pv.add_argument("--out", default=None)
    pv.set_defaults(func=_cmd_verify)

    pr = sub.add_parser("report", help="render a client-ready evidence report")
    pr.add_argument("root", nargs="?", default=".")
    pr.add_argument("--format", choices=("markdown", "html", "json"), default="markdown")
    pr.add_argument("--out", default=None)
    pr.set_defaults(func=_cmd_report)

    prb = sub.add_parser("rollback", help="restore files from an install manifest (dry-run by default)")
    prb.add_argument("root", nargs="?", default=".")
    prb.add_argument("--manifest", default=None)
    prb.add_argument("--write", action="store_true")
    prb.add_argument("--force", action="store_true")
    prb.add_argument("--json", action="store_true")
    prb.add_argument("--out", default=None)
    prb.set_defaults(func=_cmd_rollback)
