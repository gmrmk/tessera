"""dle-govern - the governance CLI an org's CI / git hook calls.

    dle-govern ingest --org acme --repo api --diff-file change.patch --author alice --agent claude
    dle-govern scan   --diff-file change.patch        # dry check, no DB write; exits 1 on HIGH/CRITICAL
    dle-govern report --org acme [--json]
    dle-govern verify-chain --org acme                # exits 1 if the tamper-evident chain is broken
    dle-govern verify-grounding                        # exits 1 if any cited source is past its re-verify cadence
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path

from .chain import GovernanceChain
from .ingest import Attribution, ingest_change, parse_diff
from .report import org_report, org_summary
from .safety.engine import scan_lines
from .store import GovernanceStore

DEFAULT_DB = os.environ.get("DLE_GOV_DB", ".governance/governance.db")


def _open(db: str):
    store = GovernanceStore(db)
    return store, GovernanceChain(store)


def _read_diff(path: str) -> str:
    # CLI hygiene: a missing/unreadable file or non-UTF-8 bytes should yield a clean
    # message + nonzero exit, not a raw traceback (this tool is wired into CI/git hooks).
    # errors='replace' lets the scan proceed on real-world mixed-encoding patches.
    if path == "-":
        return sys.stdin.buffer.read().decode("utf-8", errors="replace")
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as exc:
        raise SystemExit(f"dle-govern: cannot read diff '{path}': {exc.__class__.__name__}")


def _cmd_ingest(args) -> int:
    store, chain = _open(args.db)
    attr = Attribution(author=args.author or "unknown", agent=args.agent or "human")
    res = ingest_change(store, chain, args.org, args.repo, _read_diff(args.diff_file), attr, sha=args.sha)
    print(json.dumps({k: v for k, v in res.items() if k != "findings"}, indent=2))
    for f in res["findings"]:
        print(f"  [{f.severity}] {f.check_id}  {f.file}:{f.line}  | {f.framework}")
    return 0


def _cmd_scan(args) -> int:
    findings = []
    for path, added in parse_diff(_read_diff(args.diff_file)):
        findings.extend(scan_lines(path, added))
    for f in findings:
        print(f"[{f.severity}] {f.check_id}  {f.file}:{f.line}  | {f.framework}")
        print(f"    fix: {f.fix_hint}")
    print(f"\n{len(findings)} finding(s)")
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


def _cmd_report(args) -> int:
    store, chain = _open(args.db)
    if args.json:
        print(json.dumps(org_summary(store, chain, args.org), indent=2, default=str))
    else:
        print(org_report(store, chain, args.org))
    return 0


def _cmd_verify_chain(args) -> int:
    store, chain = _open(args.db)
    res = chain.verify(args.org)
    print(json.dumps(res, indent=2))
    if not res.get("signed"):
        print("warning: keyless verification only catches accidental edits; "
              "set DLE_CHAIN_KEY for tamper-evidence.", file=sys.stderr)
    return 0 if res["ok"] else 1


def _cmd_dashboard(args) -> int:
    from .dashboard import render_dashboard
    store, chain = _open(args.db)
    doc = render_dashboard(store, chain, args.org)
    if args.out:
        Path(args.out).write_text(doc, encoding="utf-8")
        print(f"wrote {len(doc)} bytes to {args.out}")
    else:
        print(doc)
    return 0


def _cmd_compliance(args) -> int:
    from .compliance import compliance_data, compliance_report
    store, chain = _open(args.db)
    if args.json:
        print(json.dumps(compliance_data(store, chain, args.org), indent=2, default=str))
    else:
        print(compliance_report(store, chain, args.org))
    return 0


def _cmd_verify_grounding(args) -> int:
    from datetime import date

    from .compliance import COMPLIANCE_FRAMEWORKS
    from .safety import grounding as G

    today = args.today or date.today().isoformat()
    registries = {"grounding": G.GROUNDING, "compliance": COMPLIANCE_FRAMEWORKS}
    overdue = {name: G.stale(today, args.max_age_days, reg) for name, reg in registries.items()}
    overdue = {name: ids for name, ids in overdue.items() if ids}
    if not overdue:
        print(f"all cited sources fresh as of {today} (cadence {args.max_age_days}d)")
        return 0
    print(f"STALE as of {today} (cadence {args.max_age_days}d):")
    for name, ids in overdue.items():
        for fid in ids:
            lv = registries[name][fid].get("last_verified", "?")
            print(f"  [{name}] {fid}  last_verified={lv}")
    print(f"\n{sum(len(v) for v in overdue.values())} source(s) need re-verification (re-fetch URL, confirm clause, bump last_verified).")
    return 1


def _cmd_backup(args) -> int:
    from . import backup as B
    print(json.dumps(B.backup(args.db, args.out), indent=2))
    return 0


def _cmd_restore(args) -> int:
    from . import backup as B
    r = B.restore(args.backup_file, args.dest, args.manifest)
    print(json.dumps(r, indent=2, default=str))
    return 0 if (r["sha_ok"] and r["all_chains_ok"]) else 1


def _cmd_retention(args) -> int:
    from . import backup as B
    print(json.dumps(B.retention_status(args.db, args.days), indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dle-govern", description="agent-agnostic governance & safety")
    p.add_argument("--db", default=DEFAULT_DB, help=f"governance db path (default: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="record + scan a change")
    pi.add_argument("--org", required=True); pi.add_argument("--repo", required=True)
    pi.add_argument("--diff-file", required=True, help="path to a unified diff, or '-' for stdin")
    pi.add_argument("--author", default=None); pi.add_argument("--agent", default=None)
    pi.add_argument("--sha", default=None); pi.set_defaults(func=_cmd_ingest)

    ps = sub.add_parser("scan", help="dry safety scan of a diff (no DB write)")
    ps.add_argument("--diff-file", required=True); ps.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("report", help="org governance report")
    pr.add_argument("--org", required=True); pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=_cmd_report)

    pv = sub.add_parser("verify-chain", help="verify the tamper-evident audit chain")
    pv.add_argument("--org", required=True); pv.set_defaults(func=_cmd_verify_chain)

    pd = sub.add_parser("dashboard", help="render a self-contained HTML dashboard for an org")
    pd.add_argument("--org", required=True)
    pd.add_argument("--out", default=None, help="write HTML here; default stdout")
    pd.set_defaults(func=_cmd_dashboard)

    pco = sub.add_parser("compliance", help="map the org's posture to cited control families")
    pco.add_argument("--org", required=True); pco.add_argument("--json", action="store_true")
    pco.set_defaults(func=_cmd_compliance)

    pg = sub.add_parser("verify-grounding", help="flag cited sources past the re-verification cadence")
    pg.add_argument("--today", default=None, help="ISO date to evaluate against (default: today)")
    # 90-day re-verification cadence, applied uniformly to both registries (grounding +
    # compliance) and evaluated against --today (defaults to the system clock).
    pg.add_argument("--max-age-days", type=int, default=90)
    pg.set_defaults(func=_cmd_verify_grounding)

    pb = sub.add_parser("backup", help="snapshot the audit DB + write an integrity manifest")
    pb.add_argument("--out", required=True, help="backup directory")
    pb.set_defaults(func=_cmd_backup)

    prs = sub.add_parser("restore", help="restore a backup (re-checks SHA + re-verifies the chain)")
    prs.add_argument("--backup-file", required=True)
    prs.add_argument("--dest", required=True, help="destination db path")
    prs.add_argument("--manifest", default=None, help="manifest json for the SHA integrity check")
    prs.set_defaults(func=_cmd_restore)

    prt = sub.add_parser("retention", help="report changes past the retention window (no deletion)")
    prt.add_argument("--days", type=int, required=True)
    prt.set_defaults(func=_cmd_retention)

    from ..hardening.cli import configure_parser as configure_harden_parser

    ph = sub.add_parser("harden", help="convert Claude policy into tested project hooks")
    configure_harden_parser(ph)
    return p


def main(argv: list[str] | None = None) -> int:
    # Scanned code can contain any character; emit UTF-8 so a cp1252/Windows
    # console (or a pipe to a file) never crashes on it.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, io.UnsupportedOperation):
            pass  # stream lacks reconfigure (e.g. a plain pipe / already-detached buffer)
    args = build_parser().parse_args(argv)
    return args.func(args)


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
