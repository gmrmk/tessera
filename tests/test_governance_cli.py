"""CLI surface - the dle-govern subcommands return the right exit codes + effects."""
from __future__ import annotations

from _govfixtures import DIRTY

from dual_log_engine.governance.cli import main
from dual_log_engine.governance.store import GovernanceStore

CLEAN = "--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,2 @@\n import os\n+y = add(1, 2)\n"


def _diff(tmp_path, content: str) -> str:
    p = tmp_path / "d.patch"
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_cli_scan_exits_1_on_high_severity(tmp_path):
    assert main(["scan", "--diff-file", _diff(tmp_path, DIRTY)]) == 1


def test_cli_scan_exits_0_on_clean(tmp_path):
    assert main(["scan", "--diff-file", _diff(tmp_path, CLEAN)]) == 0


def test_cli_ingest_report_compliance(tmp_path):
    db = str(tmp_path / "g.db")
    assert main(["--db", db, "ingest", "--org", "acme", "--repo", "api",
                 "--diff-file", _diff(tmp_path, DIRTY), "--agent", "claude"]) == 0
    assert main(["--db", db, "report", "--org", "acme"]) == 0
    assert main(["--db", db, "report", "--org", "acme", "--json"]) == 0
    assert main(["--db", db, "compliance", "--org", "acme"]) == 0


def test_cli_verify_chain_ok_then_broken(tmp_path):
    db = str(tmp_path / "g.db")
    main(["--db", db, "ingest", "--org", "acme", "--repo", "api", "--diff-file", _diff(tmp_path, DIRTY)])
    assert main(["--db", db, "verify-chain", "--org", "acme"]) == 0
    GovernanceStore(db)._tamper_for_test("acme", 1, '{"x":1}')
    assert main(["--db", db, "verify-chain", "--org", "acme"]) == 1


def test_cli_verify_grounding_fresh_vs_stale():
    assert main(["verify-grounding", "--today", "2026-06-29"]) == 0
    assert main(["verify-grounding", "--today", "2099-01-01"]) == 1


def test_cli_dashboard_writes_html(tmp_path):
    db = str(tmp_path / "g.db")
    main(["--db", db, "ingest", "--org", "acme", "--repo", "api", "--diff-file", _diff(tmp_path, DIRTY)])
    out = str(tmp_path / "dash.html")
    assert main(["--db", db, "dashboard", "--org", "acme", "--out", out]) == 0
    assert open(out, encoding="utf-8").read().lstrip().startswith("<")


def test_cli_backup_restore_roundtrip(tmp_path):
    # IFC: ingest -> backup --out DIR -> restore --backup-file --dest --manifest, all exit 0.
    db = str(tmp_path / "g.db")
    assert main(["--db", db, "ingest", "--org", "acme", "--repo", "api",
                 "--diff-file", _diff(tmp_path, DIRTY), "--agent", "claude"]) == 0
    bdir = tmp_path / "bk"
    assert main(["--db", db, "backup", "--out", str(bdir)]) == 0
    snaps = sorted(bdir.glob("governance-*.db"))
    assert snaps, "backup wrote no snapshot"
    snap = snaps[-1]
    manifest = snap.with_name(snap.stem + ".manifest.json")
    dest = str(tmp_path / "restored.db")
    rc = main(["restore", "--backup-file", str(snap), "--dest", dest,
               "--manifest", str(manifest)])
    assert rc == 0
    # The restored DB carries the same org + a verifiable chain.
    assert "acme" in GovernanceStore(dest).orgs()


def _backup_snapshot(tmp_path):
    """ingest -> backup, returning (db, snapshot_path, manifest_path)."""
    db = str(tmp_path / "g.db")
    assert main(["--db", db, "ingest", "--org", "acme", "--repo", "api",
                 "--diff-file", _diff(tmp_path, DIRTY), "--agent", "claude"]) == 0
    bdir = tmp_path / "bk"
    assert main(["--db", db, "backup", "--out", str(bdir)]) == 0
    snap = sorted(bdir.glob("governance-*.db"))[-1]
    manifest = snap.with_name(snap.stem + ".manifest.json")
    return db, snap, manifest


def test_cli_restore_tampered_backup_exits_1(tmp_path):
    # IFC-8: a backup file whose bytes were altered no longer matches the manifest SHA,
    # so restore fails the integrity check and exits 1 (evidence is not silently trusted).
    _db, snap, manifest = _backup_snapshot(tmp_path)
    with open(snap, "r+b") as fh:  # flip one byte in the snapshot after the manifest was written
        fh.seek(0)
        first = fh.read(1)
        fh.seek(0)
        fh.write(bytes([first[0] ^ 0xFF]))
    dest = str(tmp_path / "restored.db")
    rc = main(["restore", "--backup-file", str(snap), "--dest", dest, "--manifest", str(manifest)])
    assert rc == 1


def test_cli_restore_without_manifest_fails_closed_exits_1(tmp_path):
    # IFC-8 / SEC-7: with no manifest (explicit or sibling), the snapshot's integrity cannot
    # be verified, so restore FAILS CLOSED (exit 1) rather than trusting an unverified trail.
    _db, snap, _manifest = _backup_snapshot(tmp_path)
    lone = tmp_path / "lonely.db"  # copy the snapshot away from its sibling manifest
    lone.write_bytes(snap.read_bytes())
    dest = str(tmp_path / "restored.db")
    rc = main(["restore", "--backup-file", str(lone), "--dest", dest])
    assert rc == 1


def test_cli_retention_exits_0_with_parseable_json(tmp_path, capsys):
    # IFC-8: retention is reporting-only - it exits 0 and prints the {cutoff_ts, orgs} report
    # (per-org overdue/total/oldest_ts) as parseable JSON; it deletes nothing.
    import json
    db = str(tmp_path / "g.db")
    assert main(["--db", db, "ingest", "--org", "acme", "--repo", "api",
                 "--diff-file", _diff(tmp_path, DIRTY), "--agent", "claude"]) == 0
    capsys.readouterr()  # drain the ingest command's stdout so only retention JSON remains
    assert main(["--db", db, "retention", "--days", "30"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "cutoff_ts" in payload and "acme" in payload["orgs"]
    assert payload["orgs"]["acme"]["total"] == 1


def test_cli_missing_diff_file_clean_nonzero_exit(tmp_path):
    # IFC-7 (171/172): a nonexistent --diff-file is a clean nonzero SystemExit, not a traceback.
    import pytest
    missing = str(tmp_path / "does-not-exist.patch")
    with pytest.raises(SystemExit) as ei:
        main(["scan", "--diff-file", missing])
    assert ei.value.code not in (0, None)
