"""GovernanceStore - SQLite tables for changes, findings, and the hash chain.

Mirrors the engine's SqliteStore pattern (WAL, busy_timeout, indexed by org).
``org`` is the isolation key - the engine's multi-tenancy, reused: org = tenant.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional


def _tenant_key(org) -> str:
    """Canonical tenant key. Coerced to a stripped string so a JSON-numeric `org`
    (e.g. 123) cannot collide with the string tenant "123" via SQLite TEXT affinity,
    and an empty/whitespace tenant is rejected outright (no silent cross-tenant write)."""
    key = str(org).strip()
    if not key or not any(ch.isprintable() and not ch.isspace() for ch in key):
        raise ValueError("org (tenant id) must be a non-empty, visible string")  # reject zero-width/BOM-only
    if "|" in key:
        # '|' is the anchor-preimage field separator (chain._anchor_mac frames org|seq|head_mac);
        # forbidding it in the tenant key keeps that framing unambiguous (no org/seq boundary spoof).
        raise ValueError("org (tenant id) must not contain '|'")
    return key

_SCHEMA = """
CREATE TABLE IF NOT EXISTS changes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    org       TEXT NOT NULL,
    repo      TEXT NOT NULL,
    sha       TEXT,
    author    TEXT,
    agent     TEXT,
    ts        REAL NOT NULL,
    summary   TEXT,
    n_findings INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_changes_org ON changes(org, repo);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id     INTEGER NOT NULL,
    org           TEXT NOT NULL,
    repo          TEXT NOT NULL,
    check_id      TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    file          TEXT,
    line          INTEGER,
    snippet       TEXT,
    framework     TEXT,
    framework_url TEXT,
    clause        TEXT,
    verified      INTEGER NOT NULL DEFAULT 1,
    ts            REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org, repo, severity);

CREATE TABLE IF NOT EXISTS chain (
    org        TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    prev_hash  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    -- ts is informational wall-clock (time.time()): non-monotonic and NOT covered by the MAC,
    -- so a DB-write attacker can edit it without breaking the chain. seq is the signed ordering
    -- authority; never treat ts as tamper-protected ordering. (Same applies to changes/findings ts.)
    ts         REAL NOT NULL,
    PRIMARY KEY (org, seq)
);

CREATE TABLE IF NOT EXISTS chain_anchor (
    org        TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL,
    head_mac   TEXT NOT NULL,
    anchor_mac TEXT NOT NULL,
    ts         REAL NOT NULL
);
"""


class GovernanceStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # 5000ms: wait up to 5s for a lock (e.g. a brief WAL checkpoint) before raising
        # "database is locked". The documented single-writer assumption keeps real contention rare.
        self.conn.execute("PRAGMA busy_timeout=5000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- changes ------------------------------------------------------------ #

    def add_change(self, org, repo, sha, author, agent, summary) -> int:
        org = _tenant_key(org)
        cur = self.conn.execute(
            "INSERT INTO changes(org, repo, sha, author, agent, ts, summary) VALUES (?,?,?,?,?,?,?)",
            (org, repo, sha, author, agent, time.time(), summary))
        self.conn.commit()
        return int(cur.lastrowid)

    def set_change_findings(self, org, change_id: int, n: int) -> None:
        org = _tenant_key(org)
        self.conn.execute("UPDATE changes SET n_findings=? WHERE id=? AND org=?", (n, change_id, org))
        self.conn.commit()

    def changes(self, org: str, repo: Optional[str] = None) -> list[dict]:
        org = _tenant_key(org)
        if repo is None:
            rows = self.conn.execute(
                "SELECT * FROM changes WHERE org=? ORDER BY ts DESC, id DESC", (org,))
        else:
            rows = self.conn.execute(
                "SELECT * FROM changes WHERE org=? AND repo=? ORDER BY ts DESC, id DESC", (org, repo))
        return [dict(r) for r in rows]

    # --- findings ----------------------------------------------------------- #

    def add_finding(self, change_id, org, repo, finding: dict) -> int:
        org = _tenant_key(org)
        cur = self.conn.execute(
            "INSERT INTO findings(change_id, org, repo, check_id, category, severity, file, line, "
            "snippet, framework, framework_url, clause, verified, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (change_id, org, repo, finding["check_id"], finding["category"], finding["severity"],
             finding.get("file"), finding.get("line"), finding.get("snippet"),
             finding.get("framework"), finding.get("framework_url"), finding.get("clause"),
             1 if finding.get("verified", True) else 0, time.time()))
        self.conn.commit()
        return int(cur.lastrowid)

    def findings(self, org: str, repo: Optional[str] = None) -> list[dict]:
        org = _tenant_key(org)
        if repo is None:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE org=? ORDER BY ts DESC, id DESC", (org,))
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE org=? AND repo=? ORDER BY ts DESC, id DESC", (org, repo))
        return [dict(r) for r in rows]

    def severity_counts(self, org: str) -> dict:
        org = _tenant_key(org)
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE org=? GROUP BY severity", (org,))
        return {r["severity"]: r["n"] for r in rows}

    def orgs(self) -> list[str]:
        """Distinct tenant ids present in the store (changes or chain)."""
        rows = self.conn.execute("SELECT org FROM changes UNION SELECT org FROM chain")
        return sorted(r[0] for r in rows)

    # --- chain (raw rows; hashing logic lives in chain.py) ------------------ #

    def chain_head(self, org: str) -> tuple[int, Optional[str]]:
        org = _tenant_key(org)
        row = self.conn.execute(
            "SELECT seq, entry_hash FROM chain WHERE org=? ORDER BY seq DESC LIMIT 1", (org,)).fetchone()
        return (int(row["seq"]), row["entry_hash"]) if row else (0, None)

    def append_chain_and_anchor(self, org, seq, prev_hash, payload, entry_hash, anchor_mac) -> None:
        """Append the chain row AND update the signed anchor in ONE transaction, so a crash
        can never leave the anchor pointing past (or behind) the chain head - which would make
        verify() falsely report truncation. `with self.conn:` runs both INSERTs in a single
        implicit transaction (commit on success, roll back on error); no explicit BEGIN, which
        would clash with sqlite3's implicit transaction management."""
        org = _tenant_key(org)
        now = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT INTO chain(org, seq, prev_hash, payload, entry_hash, ts) VALUES (?,?,?,?,?,?)",
                (org, seq, prev_hash, payload, entry_hash, now))
            self.conn.execute(
                "INSERT INTO chain_anchor(org, seq, head_mac, anchor_mac, ts) VALUES (?,?,?,?,?) "
                "ON CONFLICT(org) DO UPDATE SET seq=excluded.seq, head_mac=excluded.head_mac, "
                "anchor_mac=excluded.anchor_mac, ts=excluded.ts",
                (org, seq, entry_hash, anchor_mac, now))

    def chain_rows(self, org: str) -> list[dict]:
        org = _tenant_key(org)
        rows = self.conn.execute("SELECT * FROM chain WHERE org=? ORDER BY seq ASC", (org,))
        return [dict(r) for r in rows]

    # --- chain anchor (the signed head/length witness, for truncation detection) --- #
    # The anchor is written atomically with its chain entry by append_chain_and_anchor above.

    def get_anchor(self, org) -> Optional[dict]:
        org = _tenant_key(org)
        row = self.conn.execute(
            "SELECT seq, head_mac, anchor_mac FROM chain_anchor WHERE org=?", (org,)).fetchone()
        return dict(row) if row else None

    def _tamper_for_test(self, org: str, seq: int, new_payload: str) -> None:
        """Test-only: mutate a stored payload WITHOUT updating its hash, to prove
        verify_chain detects tampering. Never used in production paths."""
        self.conn.execute("UPDATE chain SET payload=? WHERE org=? AND seq=?", (new_payload, org, seq))
        self.conn.commit()
