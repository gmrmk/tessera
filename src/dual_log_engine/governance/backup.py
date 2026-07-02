"""backup.py - integrity-checked backup + restore of the governance audit DB.

The audit DB IS the evidence, so durability is a governance control, not an
afterthought. backup() takes a consistent SQLite snapshot (the online backup API,
safe with WAL) and writes a manifest carrying a SHA-256 of the snapshot plus
per-org change/finding counts and chain heads. restore() re-checks the SHA before
trusting the file, then re-runs the chain verification on every org, so a passing
restore shows the trail's integrity held (verify-backed, not an absolute guarantee).

Maps to the retention / restorability obligations the regulator brief identifies
as the #1 cross-regime gap: SOC 2 CC2.1 ('retained'), FDA 21 CFR 11.10(c), ISO
27001 Clauses 9.1/9.2.2 + A.8.10, GDPR Art. 32(1)(c), EU AI Act Art. 19 / 26(6).

ASCII source (no BOM / mojibake) so it passes the repo's pre-commit guard.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from pathlib import Path

from .chain import GovernanceChain
from .store import GovernanceStore

# Fixed-day seconds (UTC); ignores DST/leap-seconds. Legal-day-precise retention
# would need calendar date arithmetic, a documented design choice (see retention_status).
SECONDS_PER_DAY = 86400


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot(src_db: str, dest: Path) -> None:
    """A consistent SQLite snapshot via the online backup API (safe with WAL)."""
    src = sqlite3.connect(src_db)
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def backup(db_path: str, backup_dir: str, now: float | None = None) -> dict:
    """Snapshot the audit DB and write an integrity manifest; returns the manifest."""
    ts = time.time() if now is None else now
    bdir = Path(backup_dir)
    bdir.mkdir(parents=True, exist_ok=True)
    stamp = str(int(ts))
    snap = bdir / f"governance-{stamp}.db"
    # int(ts) stamps at second granularity: two backups in the same wall-clock second
    # would target the same snapshot/manifest path. Refuse to clobber an existing snapshot
    # so a same-second backup fails loud rather than silently overwriting evidence.
    if snap.exists():
        raise FileExistsError(f"snapshot already exists for this stamp: {snap}")
    _snapshot(db_path, snap)

    store = GovernanceStore(str(snap))
    try:
        manifest = {
            "backup_file": snap.name,
            "manifest_file": f"governance-{stamp}.manifest.json",
            "sha256": _sha256(snap),
            "ts": ts,
            "orgs": {
                org: {
                    "changes": len(store.changes(org)),
                    "findings": len(store.findings(org)),
                    "chain_head": store.chain_head(org)[1],
                }
                for org in store.orgs()
            },
        }
    finally:
        store.close()  # release the snapshot handle (and its -wal/-shm) before returning
    (bdir / manifest["manifest_file"]).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def restore(backup_file: str, dest_db: str, manifest_file: str | None = None,
            force: bool = False) -> dict:
    """Restore a backup to dest_db after re-checking its SHA, then re-verify every org's chain.

    The manifest (passed explicitly, or the sibling written at backup time) gates the
    restore: if it is missing OR unreadable/malformed, integrity cannot be verified and the
    restore FAILS CLOSED (nothing written, sha_ok=False); if the SHA does not match, the
    corrupt file is NOT restored. You never trust an unverified or damaged trail.

    Restoring over an existing non-empty dest_db would destroy a live evidence DB, so it
    FAILS CLOSED unless force=True. A SHA-matched-but-empty restore (manifest recorded orgs
    yet the restored store has none) is flagged via empty_restore.
    """
    src = Path(backup_file)
    # Locate the manifest: explicit, else the sibling written at backup time. With NO
    # manifest the snapshot's integrity cannot be verified, so FAIL CLOSED rather than
    # restore an unverifiable trail and falsely report sha_ok=True.
    mpath = Path(manifest_file) if manifest_file else src.with_name(src.stem + ".manifest.json")
    if not mpath.exists():
        return {"restored_to": None, "sha_ok": False, "manifest_checked": False,
                "reason": "no manifest found; snapshot integrity cannot be verified",
                "chains": {}, "all_chains_ok": False}
    # A present-but-malformed/unreadable manifest is an unverifiable trail too: fail closed
    # with the same shape rather than letting json.loads raise out of restore().
    try:
        man = json.loads(mpath.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {"restored_to": None, "sha_ok": False, "manifest_checked": True,
                "reason": "manifest unreadable/malformed; snapshot integrity cannot be verified",
                "chains": {}, "all_chains_ok": False}
    expected = man.get("sha256")
    actual = _sha256(src)
    sha_ok = expected is not None and actual == expected
    if not sha_ok:
        return {"restored_to": None, "sha_ok": False, "manifest_checked": True,
                "expected_sha": expected, "actual_sha": actual, "chains": {}, "all_chains_ok": False}

    dest = Path(dest_db)
    # Refuse to clobber an existing non-empty dest (could be a live evidence DB) unless
    # the caller explicitly opts in with force=True.
    if dest.exists() and dest.stat().st_size > 0 and not force:
        return {"restored_to": None, "sha_ok": True, "manifest_checked": True,
                "expected_sha": expected, "actual_sha": actual,
                "reason": "dest exists; pass force=True to overwrite",
                "chains": {}, "all_chains_ok": False}
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Clear any stale dest -wal/-shm before the copy: a leftover WAL from a prior DB at this path
    # can share the snapshot's salt and be REPLAYED onto the restored .db (injecting stale rows).
    dest.unlink(missing_ok=True)
    Path(f"{dest}-wal").unlink(missing_ok=True)
    Path(f"{dest}-shm").unlink(missing_ok=True)
    shutil.copy2(src, dest)
    store = GovernanceStore(str(dest))
    try:
        chain = GovernanceChain(store)
        restored_orgs = store.orgs()
        chains = {org: chain.verify(org) for org in restored_orgs}
    finally:
        store.close()
    # Vacuous-restore guard: if the manifest recorded >=1 org but the restored store has
    # none, the SHA matched an empty/truncated DB - surface it instead of a silent success.
    empty_restore = bool(man.get("orgs")) and len(restored_orgs) == 0
    return {
        "restored_to": str(dest),
        "sha_ok": True,
        "manifest_checked": True,
        "expected_sha": expected,
        "actual_sha": actual,
        "empty_restore": empty_restore,
        "chains": chains,
        "all_chains_ok": (all(c["ok"] for c in chains.values()) if chains else True) and not empty_restore,
    }


def retention_status(db_path: str, retention_days: int, now: float | None = None) -> dict:
    """Report changes older than the retention window, per org (informational; no deletion).

    The append-only chain means timed DELETION needs a crypto-shred / tombstone
    design that preserves chain verifiability (tracked in compliance.PENDING_REGIMES
    as the append-only-vs-erasure tension). This surfaces what is past the window so
    an operator can act, without breaking the tamper-evident trail.
    """
    ts = time.time() if now is None else now
    cutoff = ts - retention_days * SECONDS_PER_DAY
    store = GovernanceStore(db_path)
    orgs = {}
    try:
        for org in store.orgs():
            changes = store.changes(org)
            orgs[org] = {
                "retention_days": retention_days,
                "overdue": sum(1 for c in changes if c["ts"] < cutoff),
                "total": len(changes),
                "oldest_ts": min((c["ts"] for c in changes), default=None),
            }
    finally:
        store.close()
    return {"cutoff_ts": cutoff, "orgs": orgs}
