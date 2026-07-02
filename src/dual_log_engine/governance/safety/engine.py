"""Safety engine - run the grounded checks through the two-signal gate.

`scan_lines` takes the *added* lines of a change and returns `Finding`s. A line
becomes a finding only when a check's `detect` fires AND its independent `verify`
confirms. Every finding carries its authoritative source, and known secret formats
in the snippet are redacted on a best-effort basis before it leaves this module (a
security scanner that prints the secret it caught is the bug - mirrors
trust-but-verify's AB-5). Redaction is best-effort, not exhaustive (see below).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .checks import CHECKS
from .grounding import cite

# Best-effort redaction of known secret forms from each snippet before it is stored or reported.
_REDACT_TOKEN = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
# Redact the value of any assignment whose KEY contains a secret-ish word (substring,
# not an exact allowlist - closes the 'gitlab_token'/'db_password'/'MY_API_KEY' gap)
# without blanket-masking every string literal (which would erase finding evidence).
_REDACT_ASSIGN = re.compile(
    r"(?i)([\w.\-]*(?:api|key|secret|token|password|passwd|cred|auth)[\w.\-]*\s*[:=]\s*['\"])"
    r"([^'\"]{4,})(['\"])")

_MAX_SCAN_LINE = 2000  # bound per-line scanning work (defense vs a crafted-diff ReDoS/DoS).
# NOTE: content past this column is also unscanned AND unredacted - a documented
# coverage gap (a secret beyond col 2000 is neither detected nor masked); see
# SECURITY-HARDENING.md.

# A high-entropy quoted literal with no known prefix AND no secret-ish key name is the
# residual leak path. For a security audit store, masking a POSSIBLE secret beats leaking
# one, so a quoted 20+ char mixed-case-and-digit token is masked by default - a deliberate
# bias toward redaction. Lower-entropy literals are not matched and keep their evidence
# value (SQL/sentences carry spaces; ids/SHAs are single-char-class), and a finding's real
# evidence is its check/file/line/framework, not the literal. (Known-format secrets of any
# length are caught by _REDACT_TOKEN regardless of entropy.)
_REDACT_ENTROPY = re.compile(r"(['\"])([A-Za-z0-9][A-Za-z0-9+/=_\-]{19,})(['\"])")
# Credentials embedded INSIDE a larger string (not a standalone quoted token) co-occur with
# the very checks that fire (command-injection / ssrf), so they reach the store unless caught
# here. This is BEST-EFFORT + pattern-based, NOT exhaustive - it covers the common forms (URL
# basic-auth, secret query params, bearer tokens, explicit DB password flags). The robust
# control is to not hardcode credentials at all (which the secret-hardcoded check flags) and,
# longer term, a dedicated secret scanner; arbitrary embedded forms will not all be caught.
# Each pattern keeps group(1) (the context) and masks group(2) (the secret). Only UNAMBIGUOUS
# credential syntax is matched: the bare `-p<x>` mysql shorthand is deliberately NOT here -
# it is indistinguishable from a docker port (-p3306:3306), cp -p, or grep -pattern without
# semantic analysis, and masking it corrupts legitimate command evidence.
_REDACT_URL_AUTH = re.compile(r"(://[^/\s:@]*:)([^/\s@]{3,})(?=@)")                     # ://user:PASS@ or ://:PASS@
_REDACT_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access[_-]?token|api[_-]?key|apikey|client[_-]?secret|token|secret|signature|sig|password|passwd|auth)=)"
    r"([^&\s'\"]{4,})")                                                                # ?token=PASS / ?client_secret=PASS
_REDACT_BEARER = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]{8,})")                   # Authorization: Bearer X
_REDACT_DB_PW = re.compile(r"(?i)((?:--password|pgpassword|mysql_pwd)=)(\S{4,})")       # explicit DB pw flags (= form only; bare --password is an interactive prompt, not an inline value)
_REDACT_EMBEDDED = (_REDACT_URL_AUTH, _REDACT_QUERY_SECRET, _REDACT_BEARER, _REDACT_DB_PW)


def _looks_secret(s: str) -> bool:
    return any(c.islower() for c in s) and any(c.isupper() for c in s) and any(c.isdigit() for c in s)


def redact(text: str) -> str:
    text = _REDACT_TOKEN.sub("<REDACTED-SECRET>", text)
    text = _REDACT_ASSIGN.sub(lambda m: m.group(1) + "<REDACTED>" + m.group(3), text)
    for _pat in _REDACT_EMBEDDED:                          # URL auth / query secret / bearer / DB pw flags
        text = _pat.sub(lambda m: m.group(1) + "<REDACTED>", text)
    text = _REDACT_ENTROPY.sub(
        lambda m: m.group(1) + "<REDACTED>" + m.group(3) if _looks_secret(m.group(2)) else m.group(0), text)
    return text


# Findings MUST be built via scan_lines(): redact() runs there, not in __post_init__ -
# directly constructing Finding(snippet=raw) would bypass redaction.
@dataclass(frozen=True)
class Finding:
    check_id: str
    category: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    framework: str
    framework_url: str
    clause: str
    fix_hint: str = ""
    verified: bool = True

    def as_row(self) -> dict:
        return {
            "check_id": self.check_id, "category": self.category, "severity": self.severity,
            "file": self.file, "line": self.line, "snippet": self.snippet,
            "framework": self.framework, "framework_url": self.framework_url,
            "clause": self.clause, "verified": self.verified,
        }


def scan_lines(file: str, added_lines: list[tuple[int, str]]) -> list[Finding]:
    """Scan a file's added lines. `added_lines` = [(new_line_number, text), ...]."""
    findings: list[Finding] = []
    for lineno, text in added_lines:
        if len(text) > _MAX_SCAN_LINE:
            text = text[:_MAX_SCAN_LINE]  # bound per-line work (defense vs a crafted-diff DoS)
        for chk in CHECKS:
            m = chk.detect.search(text)
            if not m:
                continue  # signal 1 (detect) absent
            if not chk.verify(text, m):
                continue  # signal 2 (verify) refutes -> drop. This is the two-signal gate.
            c = cite(chk.framework)  # raises if the check is ungrounded - no source, no finding
            findings.append(Finding(
                check_id=chk.id, category=chk.category, title=chk.title, severity=chk.severity,
                file=file, line=lineno, snippet=redact(text.strip())[:300],
                framework=c["framework"], framework_url=c["framework_url"], clause=c["clause"],
                fix_hint=chk.fix_hint, verified=True))
    return findings
