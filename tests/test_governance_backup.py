"""Backup + restore - the audit DB is the evidence, so durability is a governance control."""
from __future__ import annotations

from _govfixtures import DIRTY

from dual_log_engine.governance import backup as B
from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.ingest import Attribution, ingest_change
from dual_log_engine.governance.store import GovernanceStore


def _seed(tmp_path) -> str:
    db = str(tmp_path / "gov.db")
    store = GovernanceStore(db)
    ingest_change(store, GovernanceChain(store), "acme", "api", DIRTY, Attribution("a", "claude"))
    return db


def test_backup_writes_snapshot_and_manifest(tmp_path):
    m = B.backup(_seed(tmp_path), str(tmp_path / "backups"), now=1.0)
    assert m["sha256"] and m["orgs"]["acme"]["changes"] == 1
    assert (tmp_path / "backups" / m["backup_file"]).exists()
    assert (tmp_path / "backups" / m["manifest_file"]).exists()


def test_restore_reverifies_chain_and_counts(tmp_path):
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    r = B.restore(str(bdir / m["backup_file"]), str(tmp_path / "restored.db"), str(bdir / m["manifest_file"]))
    assert r["sha_ok"] and r["all_chains_ok"]
    s = GovernanceStore(str(tmp_path / "restored.db"))
    assert len(s.changes("acme")) == 1 and len(s.findings("acme")) >= 2


def test_restore_clears_stale_wal_before_copy(tmp_path):
    # MED: a stale dest -wal/-shm left from a PRIOR restore of the same image shares the snapshot's
    # WAL salt, so SQLite would REPLAY its frames onto the freshly copied .db (injecting ghost
    # rows). restore() must unlink dest/-wal/-shm before the copy so no stale frames are replayed.
    import shutil
    import sqlite3
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    snap = bdir / m["backup_file"]
    dest = tmp_path / "restored.db"

    # Forge a salt-matching stale WAL: copy the snapshot, open it in WAL mode, insert a GHOST row
    # without checkpointing so the row lives only in the -wal, then plant that -wal/-shm beside dest.
    prime = tmp_path / "prime.db"
    shutil.copy2(snap, prime)
    c = sqlite3.connect(str(prime))
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("INSERT INTO changes(org,repo,sha,author,agent,ts,summary) VALUES "
              "('acme','api',NULL,'ghost','ghost',1.0,'STALE GHOST ROW')")
    c.commit()
    prime_wal = tmp_path / "prime.db-wal"
    prime_shm = tmp_path / "prime.db-shm"
    shutil.copy2(prime_wal, tmp_path / "restored.db-wal")
    if prime_shm.exists():
        shutil.copy2(prime_shm, tmp_path / "restored.db-shm")
    c.close()

    r = B.restore(str(snap), str(dest), str(bdir / m["manifest_file"]))
    assert r["sha_ok"] and r["all_chains_ok"]
    s = GovernanceStore(str(dest))
    try:
        rows = s.changes("acme")
        assert all(row["summary"] != "STALE GHOST ROW" for row in rows)  # no replayed ghost frame
        assert len(rows) == 1 and len(s.findings("acme")) >= 2  # exactly the restored rows
    finally:
        s.close()


def test_restore_detects_tampered_backup(tmp_path):
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bf = tmp_path / "backups" / m["backup_file"]
    data = bytearray(bf.read_bytes()); data[100] ^= 0xFF; bf.write_bytes(bytes(data))
    r = B.restore(str(bf), str(tmp_path / "restored2.db"), str(tmp_path / "backups" / m["manifest_file"]))
    assert r["sha_ok"] is False and r["restored_to"] is None  # corruption caught before trusting the restore


def test_restore_without_manifest_fails_closed(tmp_path):
    # SEC-7: a backup with no manifest cannot be integrity-verified -> refuse to restore,
    # never report sha_ok=True (the old fail-open).
    import shutil
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    lone = tmp_path / "lone" / "snap.db"
    lone.parent.mkdir()
    shutil.copy2(tmp_path / "backups" / m["backup_file"], lone)  # copied WITHOUT its manifest
    r = B.restore(str(lone), str(tmp_path / "restored.db"))      # no manifest, no sibling
    assert r["sha_ok"] is False and r["restored_to"] is None and r["manifest_checked"] is False


def test_restore_auto_discovers_sibling_manifest(tmp_path):
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=2.0)
    bf = tmp_path / "backups" / m["backup_file"]
    r = B.restore(str(bf), str(tmp_path / "restored2.db"))  # no explicit manifest -> sibling found
    assert r["sha_ok"] and r["manifest_checked"] and r["all_chains_ok"]


def test_retention_status_flags_overdue(tmp_path):
    import time
    db = _seed(tmp_path)
    future = time.time() + 100 * 86400
    assert B.retention_status(db, retention_days=1, now=future)["orgs"]["acme"]["overdue"] == 1
    assert B.retention_status(db, retention_days=3650, now=time.time())["orgs"]["acme"]["overdue"] == 0


def test_db_lives_at_configured_durable_path(tmp_path):
    # NEW-1: the audit DB is placed exactly where configured (DLE_GOV_DB), parent
    # dirs created - a durable home, not a fixed temp default.
    home = tmp_path / "var" / "governance" / "gov.db"
    s = GovernanceStore(str(home))
    s.add_change("acme", "api", None, "alice", "claude", "x")
    assert home.exists()


def test_backup_refuses_same_second_overwrite(tmp_path):
    # n190: int(ts) is second-granularity; a second backup at the same stamp would clobber
    # the first snapshot/manifest. It must fail loud, not silently overwrite evidence.
    import pytest
    db = _seed(tmp_path)
    bdir = str(tmp_path / "backups")
    B.backup(db, bdir, now=1.0)
    with pytest.raises(FileExistsError):
        B.backup(db, bdir, now=1.0)


def test_restore_malformed_manifest_fails_closed(tmp_path):
    # n198: a present-but-corrupt manifest cannot verify integrity -> fail closed with the
    # standard shape, never raise out of restore().
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    (bdir / m["manifest_file"]).write_text("{not valid json", encoding="utf-8")
    r = B.restore(str(bdir / m["backup_file"]), str(tmp_path / "restored.db"),
                  str(bdir / m["manifest_file"]))
    assert r["sha_ok"] is False and r["restored_to"] is None
    assert r["manifest_checked"] is True and r["all_chains_ok"] is False


def test_restore_refuses_to_clobber_existing_dest(tmp_path):
    # n200: restoring over an existing non-empty dest could destroy a live evidence DB ->
    # fail closed unless force=True.
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    dest = tmp_path / "live.db"
    dest.write_bytes(b"existing evidence")  # a non-empty dest already on disk
    r = B.restore(str(bdir / m["backup_file"]), str(dest), str(bdir / m["manifest_file"]))
    assert r["restored_to"] is None and r["all_chains_ok"] is False
    assert dest.read_bytes() == b"existing evidence"  # untouched
    # force=True proceeds with the restore
    r2 = B.restore(str(bdir / m["backup_file"]), str(dest), str(bdir / m["manifest_file"]), force=True)
    assert r2["restored_to"] == str(dest) and r2["all_chains_ok"]


def test_restore_flags_vacuously_empty_restore(tmp_path):
    # n201: a SHA-matched but org-less DB (manifest recorded orgs) must not pass as success.
    import json
    db = _seed(tmp_path)
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    snap = bdir / m["backup_file"]
    # Build an EMPTY governance DB, re-SHA the manifest over it but keep its recorded orgs.
    empty = tmp_path / "empty.db"
    GovernanceStore(str(empty)).close()
    snap.write_bytes(empty.read_bytes())
    man = json.loads((bdir / m["manifest_file"]).read_text(encoding="utf-8"))
    man["sha256"] = B._sha256(snap)  # make the SHA match the empty DB; orgs stays populated
    (bdir / m["manifest_file"]).write_text(json.dumps(man), encoding="utf-8")
    r = B.restore(str(snap), str(tmp_path / "restored.db"), str(bdir / m["manifest_file"]))
    assert r["sha_ok"] is True and r["empty_restore"] is True and r["all_chains_ok"] is False


def test_backup_captures_uncheckpointed_wal(tmp_path):
    # census C3 (proof): the sqlite3 online backup API merges committed-but-uncheckpointed WAL
    # data into a standalone snapshot, so a backup taken with NO explicit checkpoint is complete
    # (the manifest SHA over the .db needs no -wal/-shm sidecars). Proves "safe with WAL", not assumes.
    db = str(tmp_path / "live.db")           # file-backed -> WAL mode is on (store __init__)
    s = GovernanceStore(db)
    ingest_change(s, GovernanceChain(s), "acme", "api", DIRTY, Attribution("a", "claude"))
    # keep s OPEN (no close, no checkpoint) so the committed rows sit in the WAL, not the main db
    m = B.backup(db, str(tmp_path / "backups"), now=1.0)
    bdir = tmp_path / "backups"
    # restore copies ONLY the snapshot .db (not any -wal sidecar). If it recovers every row and a
    # verifying chain, the online backup API must have merged the uncheckpointed WAL into the .db -
    # i.e. the snapshot is self-complete. (A -wal beside the snapshot is just backup()'s own
    # count-read opening it in WAL mode; restore never touches it.)
    r = B.restore(str(bdir / m["backup_file"]), str(tmp_path / "restored.db"),
                  str(bdir / m["manifest_file"]))
    assert r["sha_ok"] and r["all_chains_ok"]
    rs = GovernanceStore(str(tmp_path / "restored.db"))
    assert len(rs.changes("acme")) == 1 and len(rs.findings("acme")) >= 2  # WAL rows captured
    assert GovernanceChain(rs).verify("acme")["ok"]
