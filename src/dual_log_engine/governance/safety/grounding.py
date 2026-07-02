"""Grounding - the authoritative-source registry (the trust tree's leaves).

The load-bearing rule, ported from the trust-but-verify discipline:
**a check with no cited authoritative source does not ship.** Every safety check
references one entry here by id, and every finding it produces carries the source.

Each entry carries a `last_verified` date (ISO YYYY-MM-DD): the day the cited URL
and clause were last confirmed against the primary source. A version pin grounds a
check, but a pin with no freshness discipline rots into the exact "citation
theater" this registry exists to prevent.

Freshness cadence (gate available; run verify-grounding against the real clock to enforce):
- Re-verify every cited source at least every STALE_AFTER_DAYS (90) days.
- `stale(today)` lists entries past the cadence; `assert_fresh(today)` raises
  StaleGroundingError if any are - so a stale tree fails the build instead of
  quietly misleading an auditor. The gate is available via `dle-govern
  verify-grounding`, but is not yet wired into an automated CI step that runs it
  against the real clock (every in-repo test pins `today`).
- To re-verify: re-fetch the URL, confirm the clause text still matches, then bump
  `last_verified` to today; if the source moved, update name/version/url too.

ASCII source (no BOM / mojibake) so it passes the repo's pre-commit guard.
"""
from __future__ import annotations

from datetime import date

GROUNDING: dict[str, dict] = {
    "owasp-a03-2021": {
        "name": "OWASP Top 10 - A03:2021 Injection",
        "version": "2021",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "last_verified": "2026-06-29",
    },
    "cwe-89": {
        "name": "CWE-89 - SQL Injection",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "last_verified": "2026-06-29",
    },
    "cwe-79": {
        "name": "CWE-79 - Cross-site Scripting (XSS)",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "last_verified": "2026-06-29",
    },
    "cwe-798": {
        "name": "CWE-798 - Use of Hard-coded Credentials",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "last_verified": "2026-06-29",
    },
    "cwe-327": {
        "name": "CWE-327 - Use of a Broken or Risky Cryptographic Algorithm",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/327.html",
        "last_verified": "2026-06-29",
    },
    "gdpr-art5-art32": {
        "name": "GDPR Art. 5 (data minimisation) + Art. 32 (security of processing)",
        "version": "EU 2016/679",
        # EUR-Lex primary (consolidated regulation, covers both Art. 5 and Art. 32) -
        # the same authoritative source compliance.py uses, not a third-party mirror.
        "url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        "last_verified": "2026-06-29",
    },
    "cwe-22": {
        "name": "CWE-22 - Improper Limitation of a Pathname (Path Traversal)",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
        "last_verified": "2026-06-29",
    },
    "cwe-918": {
        "name": "CWE-918 - Server-Side Request Forgery (SSRF)",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/918.html",
        "last_verified": "2026-06-29",
    },
    "cwe-502": {
        "name": "CWE-502 - Deserialization of Untrusted Data",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/502.html",
        "last_verified": "2026-06-29",
    },
    "cwe-319": {
        "name": "CWE-319 - Cleartext Transmission of Sensitive Information",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/319.html",
        "last_verified": "2026-06-29",
    },
    "openssf-scorecard": {
        "name": "OpenSSF Scorecard - Pinned-Dependencies",
        "version": "current",
        "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
        "last_verified": "2026-06-29",
    },
    "cwe-78": {
        "name": "CWE-78 - Improper Neutralization of Special Elements used in an OS Command",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
        "last_verified": "2026-06-29",
    },
    "cwe-94": {
        "name": "CWE-94 - Improper Control of Generation of Code (eval/exec injection)",
        "version": "CWE 4.x",
        "url": "https://cwe.mitre.org/data/definitions/94.html",
        "last_verified": "2026-06-29",
    },
}


def cite(framework_id: str) -> dict:
    """Return {framework, framework_url, clause} for a finding, or raise if ungrounded."""
    if framework_id not in GROUNDING:
        # The discipline, enforced by construction: no source, no check.
        raise KeyError(f"ungrounded check references unknown framework {framework_id!r}")
    g = GROUNDING[framework_id]
    return {"framework": g["name"], "framework_url": g["url"], "clause": framework_id}


# --- freshness gate: keep the trust tree from rotting into citation theater ---- #

STALE_AFTER_DAYS = 90  # re-verify every cited source at least quarterly


class StaleGroundingError(RuntimeError):
    """Raised by the release gate when a cited source is past its re-verification cadence."""


def _age_days(last_verified: str, today: str) -> int:
    return (date.fromisoformat(today) - date.fromisoformat(last_verified)).days


def stale(today: str, max_age_days: int = STALE_AFTER_DAYS, registry: dict | None = None) -> list[str]:
    """Framework ids whose citation was not re-verified within max_age_days.

    `today` is an ISO date string (the caller supplies it, so this stays
    deterministic and testable). Defaults to the GROUNDING registry; pass another
    registry (e.g. compliance.COMPLIANCE_FRAMEWORKS) to gate it too.
    """
    reg = GROUNDING if registry is None else registry
    return sorted(
        fid for fid, g in reg.items()
        if _age_days(g.get("last_verified", "1970-01-01"), today) > max_age_days
    )


def assert_fresh(today: str, max_age_days: int = STALE_AFTER_DAYS, registry: dict | None = None) -> None:
    """Raise StaleGroundingError if any cited source is past the cadence (the release gate)."""
    overdue = stale(today, max_age_days, registry)
    if overdue:
        raise StaleGroundingError(
            f"{len(overdue)} grounding source(s) past the {max_age_days}-day "
            f"re-verification cadence: {', '.join(overdue)}"
        )
