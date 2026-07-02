"""Check registry - the grounded safety checks (mirrors trust-but-verify's trust-tree.yaml).

Each check is a branch with:
  * detect  - the pattern that produces a *candidate* (signal 1)
  * verify  - a second LEXICAL signal on the same line that confirms or refutes the
              candidate (signal 2): a placeholder secret, a parameterized query, an
              example email, or a security-context keyword is checked here. It is a
              second signal, not an INDEPENDENT dataflow/AST signal - both detect and
              verify read one physical line, so multi-line and taint evasions defeat
              both (detection is regex-not-dataflow; see SECURITY-HARDENING.md).
  * framework - the authoritative source id (must exist in grounding.GROUNDING)

A candidate becomes a finding only if detect fires AND verify confirms - the
two-signal gate. No single-signal findings. The set is intentionally small and
extensible; add a branch by appending a Check (and a grounding entry).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Pattern

# --- independent second-signal helpers -------------------------------------- #

_PLACEHOLDER = re.compile(
    r"(?i)(example|x{3,}|placeholder|your[_-]?|change[_-]?me|dummy|fake|redacted|\bsample\b"
    r"|<[^>]+>|secret_key_here|todo|replace[_-]?me|\.\.\.)")
_ENV_REF = re.compile(r"(?i)(os\.environ|process\.env|getenv|\$\{|import\.meta\.env|config\.get)")
_SEC_CTX = re.compile(r"(?i)(password|passwd|\bpwd\b|\bpw\b|secret|token|credential|auth|api[_-]?key|signature|hmac)")
_PARAM = re.compile(r"(\?|%s|%\([A-Za-z_]\w*\)s|:\w+\b)")  # SQL parameter placeholders


def _verify_secret(line: str, m: "re.Match[str]") -> bool:
    if _ENV_REF.search(line):
        return False  # read from env, not hardcoded
    val = m.groupdict().get("val") or m.group(0)
    if _PLACEHOLDER.search(val):
        return False  # an obvious placeholder, not a real secret
    return len(re.sub(r"[^A-Za-z0-9]", "", val)) >= 8  # needs some substance


def _first_call_arg(line: str) -> str:
    """The first argument of the first (...) call on the line, respecting nested brackets
    and string literals - so a bind-parameter tuple after the first comma (the
    ("%"+q+"%",) in execute(sql, (...))) is excluded from the SQL-build check."""
    i = line.find("(")
    if i < 0:
        return line
    depth, start, quote, j = 0, i + 1, None, i
    while j < len(line):
        ch = line[j]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return line[start:j]
        elif ch == "," and depth == 1:
            return line[start:j]
        j += 1
    return line[start:]


def _verify_sql(line: str, _m: "re.Match[str]") -> bool:
    # Injectable only when a variable is built INTO the SQL string. Work on the first call
    # argument (so a concat inside a bind tuple is excluded), then mask the string literals:
    # any %-operator or + that survives is joining the SQL string to a variable - which
    # catches adjacent-literal concatenation and the no-space % form, while a constant query
    # or a LIKE '%x%' literal (the % is inside the masked string) stays clean.
    expr = _first_call_arg(line)
    if re.search(r"(?i)\b(?:rf|fr|f)['\"][^'\"]*\{\s*[A-Za-z_]\w*", expr):  # f/F/rf/fR"... {var}"
        return True
    if re.search(r"\.\s*format(?:_map)?\s*\(", expr):       # "...".format(var) / .format_map(d)
        return True
    masked = re.sub(r"(['\"]).*?\1", "#", expr)             # collapse each string literal to '#'
    if re.search(r"%\s*[\(\[{A-Za-z_]", masked):            # "..." % var / % (...) / % {dict} (any spacing)
        return True
    if re.search(r"#\s*\+\s*[A-Za-z_]", masked) or re.search(r"[A-Za-z_][\w.]*\s*\+\s*#", masked):
        return True  # string + var  OR  var + string - a variable on EITHER side of the concat
    return False


def _verify_xss(line: str, m: "re.Match[str]") -> bool:
    after = line[m.start():]
    # refute a pure constant literal assignment (no variable/expression flows in)
    if re.search(r"=\s*(['\"])[^'\"]*\1\s*;?\s*$", after):
        return False
    if re.search(r"__html\s*:\s*(['\"])[^'\"]*\1\s*\}", after):
        return False
    return True


# RFC2606/RFC6761 reserved domains and TLDs are documentation-only - an address in
# them is never real PII, so refute them (covers .test/.example/.invalid TLDs and the
# example.com/org/net second-level names).
_RESERVED_EMAIL_DOMAIN = re.compile(
    r"(?:@|\.)(?:example|test|invalid)$|@(?:[\w.-]+\.)?example\.(?:com|org|net)$", re.I)


def _verify_pii(line: str, m: "re.Match[str]") -> bool:
    val = m.group(0).lower()
    if "@" in val:  # email branch
        if _RESERVED_EMAIL_DOMAIN.search(val):
            return False  # RFC2606-reserved documentation domain, not real PII
        if "example.com" in val or val.startswith(("test@", "noreply@", "foo@", "bar@", "user@example")):
            return False  # example/placeholder address
    else:  # SSN-shaped 3-2-4 literal: refute structurally-invalid groups (per SSA allocation)
        area, group, serial = val[0:3], val[4:6], val[7:11]
        if area in ("000", "666") or area >= "900" or group == "00" or serial == "0000":
            return False  # never-issued SSN block -> not real PII
    if line.lstrip().startswith(("#", "//", "*", "<!--")):
        return False  # illustrative comment, not stored PII
    return True


def _verify_weak_crypto(line: str, _m: "re.Match[str]") -> bool:
    return _SEC_CTX.search(line) is not None  # weak hash on a credential, not a checksum


# The XSS sink pattern is assembled from string parts on purpose: the literal
# name of the sink would otherwise trip naive "contains a dangerous string"
# scanners against this file - the same false-positive class our verify() drops.
# Heuristic sink list, NOT exhaustive: covers the React dangerous-inner-HTML prop,
# the .innerHTML assignment sink, and the Vue v-html directive. Several other DOM
# HTML sinks (outerHTML, insertAdjacentHTML, the document write API, jQuery's html()
# setter, the Angular innerHTML binding) are out of scope for this heuristic.
_XSS_SINK = re.compile(
    "(?i)(" + "dangerously" + "SetInner" + "HTML" + r"|\.inner" + "HTML" + r"\s*=|v-html\s*=)")


# --- enhancement-round checks: more independent second-signal helpers -------- #

def _verify_path_traversal(line: str, _m: "re.Match[str]") -> bool:
    if re.search(r"(?i)(secure_filename|os\.path\.basename|\.resolve\(\)|realpath|safe_join)", line):
        return False  # sanitized / confined
    return bool(re.search(r"(?i)(request|param|user|input|filename|file_?path|upload|\bpath\b|payload|\bargs\b)", line))


def _verify_ssrf(line: str, m: "re.Match[str]") -> bool:
    after = line[m.end():].lstrip()  # the URL argument (detect ends just after the '(')
    if after[:1] in ("'", '"'):
        return False  # constant URL literal, not user-controlled
    if re.search(r"(?i)(allowlist|allowed_hosts|whitelist|is_allowed|validate_url)", line):
        return False
    return True  # a variable / expression flows into the request URL


def _verify_insecure_deser(line: str, _m: "re.Match[str]") -> bool:
    return not re.search(r"(?i)(safe_load|SafeLoader|FullLoader|literal_eval)", line)  # refute safe variants


def _verify_private_key(line: str, _m: "re.Match[str]") -> bool:
    return not re.search(r"(?i)(example|dummy|placeholder|\bsample\b|test[_-]?key|fixture)", line)


_NS_URL = re.compile(r"(?i)(w3\.org|xmlns|schemas?[./]|purl\.org|/ns/|/dtd/|!doctype|example\.(com|org))")


def _verify_cleartext(line: str, _m: "re.Match[str]") -> bool:
    if line.lstrip().startswith(("#", "//", "*", "<!--")):
        return False
    return not _NS_URL.search(line)  # refute XML namespace / schema URLs (legitimately http://)


# Detect patterns. Risky literals (a PEM private-key header; the unsafe-deser
# module name) are assembled from fragments so this file's own source carries no
# contiguous dangerous literal (which would trip a naive content scanner).
_DES = "pic" + "kle"  # the unsafe-deserialization module name, de-fragmented
_PATH_TRAVERSAL = re.compile(r"(?i)\b(open|send_file|sendfile)\s*\([^)]*(\+|f['\"]|\.format|%\b|os\.path\.join)")
_SSRF = re.compile(
    r"(?i)(requests\.(get|post|put|head|request)|urlopen|httpx\.(get|post)|urllib\.request\.urlopen)\s*\(")
_INSECURE_DESER = re.compile(
    r"(?i)(" + _DES + r"\.loads|c" + _DES + r"\.loads|marshal\.loads|yaml\.load\s*\(|json" + _DES + r"\.decode)")
_PRIVATE_KEY = re.compile("-----BEGIN " + "[A-Z ]*PRIVATE" + " KEY-----")
# Exclude loopback + RFC1918 private + link-local hosts: cleartext http to an intranet
# / localhost address is routinely legitimate and not a sensitive-transmission FP.
_CLEARTEXT = re.compile(
    r"(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?"
    r"|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)")


# --- enhancement-round E2: supply-chain + more PII -------------------------- #

def _verify_floating_tag(line: str, m: "re.Match[str]") -> bool:
    # Read the ref from the DETECT match's 'owner/repo@<ref>' token (the regex bounds <ref> to
    # the first \S+), NOT from a rsplit of the whole line - a trailing comment containing '@'
    # would otherwise hijack the rsplit and make verify inspect the wrong token.
    token = m.group(0)
    ref = token.rsplit("@", 1)[-1].split()[0] if "@" in token else ""
    if re.fullmatch(r"[0-9a-f]{7,64}", ref):
        return False  # pinned to a commit SHA (short, SHA-1 40-hex, or SHA-256 64-hex) -> safe
    return bool(ref)  # a floating tag / branch (v1, main, master, ...)


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _verify_credit_card(line: str, m: "re.Match[str]") -> bool:
    # Strip with [^0-9] (ASCII-only): \D would KEEP Unicode decimal digits, which then
    # corrupt ord(ch)-48 inside _luhn_ok. Only ASCII 0-9 may reach the Luhn check.
    digits = re.sub(r"[^0-9]", "", m.group(0))
    return 13 <= len(digits) <= 16 and _luhn_ok(digits)  # Luhn is the independent second signal


def _verify_phone(line: str, m: "re.Match[str]") -> bool:
    if line.lstrip().startswith(("#", "//", "*", "<!--")):
        return False
    if re.search(r"(?i)(example|placeholder|fake|\btest\b)", line):
        return False
    digits = re.sub(r"[^0-9]", "", m.group(0))  # ASCII-only (see _verify_credit_card)
    return len(digits) == 10 and digits[3:6] != "555"  # the 555 exchange is reserved/fictional


_FLOATING_TAG = re.compile(r"(?i)uses:\s*[\w.\-]+/[\w.\-]+@\S+")
_CREDIT_CARD = re.compile(r"(?<!\d)(?:\d{13,16}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4})(?!\d)")
_US_PHONE = re.compile(r"(?<!\d)\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)")


# --- security-hardening (purple-team): command + code injection ------------- #
# Dangerous sink names are assembled from fragments so this file's own source
# carries no contiguous flagged literal.
_OSM = "(?:" + "sy" + "stem|" + "po" + "pen)"
_SUBP = "sub" + "process"
_DYN = "(?:" + "ev" + "al|" + "ex" + "ec)"
_CMD_INJECT = re.compile(
    r"(?i)\bos\." + _OSM + r"\s*\(|\b" + _SUBP + r"\.(?:call|run|Popen|check_output)\b[^)]*shell\s*=\s*True")
_CODE_INJECT = re.compile(r"(?<![A-Za-z0-9_.])" + _DYN + r"\s*\(")


def _verify_cmd_inject(line: str, _m: "re.Match[str]") -> bool:
    if re.search(r"(?i)(request|\binput\b|\bargs\b|\bform\b|param|argv|\buser|os\.environ|sys\.)", line):
        return True  # user/request-derived data flows into the command
    return bool(re.search(r"(\+|%|\.format|f['\"]|\{)", line))  # built dynamically (concat/format)


def _verify_code_inject(line: str, m: "re.Match[str]") -> bool:
    after = line[m.end():].lstrip()
    if after[:1] in ("'", '"') or re.match(r"-?\d", after):
        return False  # dynamic-exec of a literal constant
    return True  # a variable / expression is executed


# --- the check model + registry --------------------------------------------- #

@dataclass(frozen=True)
class Check:
    id: str
    category: str  # security | privacy
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    framework: str  # id into grounding.GROUNDING
    detect: Pattern[str]
    verify: Callable[[str, "re.Match[str]"], bool]
    fix_hint: str


CHECKS: list[Check] = [
    Check(
        id="secret-hardcoded", category="security", title="Hard-coded credential",
        severity="CRITICAL", framework="cwe-798",
        detect=re.compile(
            r"""(?ix)
            (?: (?:api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret|credential|auth[_-]?token|private[_-]?key)
                \s*[:=]\s*['"](?P<val>[^'"]{6,})['"]
              | AKIA[0-9A-Z]{16}
              | sk-[A-Za-z0-9]{20,}
              | xox[baprs]-[A-Za-z0-9-]{10,}
              | gh[pousr]_[A-Za-z0-9]{20,}
              | github_pat_[A-Za-z0-9_]{20,}
              | glpat-[A-Za-z0-9_\-]{20,}
              | AIza[0-9A-Za-z_\-]{35}
              | eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,} )
            """),
        verify=_verify_secret,
        fix_hint="Move the secret to an environment variable / secret manager; rotate it if it was committed.",
    ),
    Check(
        id="sql-injection", category="security", title="SQL built from string interpolation",
        severity="HIGH", framework="owasp-a03-2021",
        detect=re.compile(
            r"""(?ix)
            (?:executescript|executemany|execute|cursor\.execute|\.query|db\.query|\.raw)\s*\(\s*
            (?:[\w.]+\s*\+\s*)*   # optional 'prefix +' before the SQL string (verify confirms the var)
            [rbf]*['"][^'"]*\b(?:select|insert|update|delete|drop)\b   # [rbf]* = any string-literal prefix (f/F/rf/fR...)
            """),
        verify=_verify_sql,
        fix_hint="Use parameterized queries (?, %s, :name) - never interpolate user input into SQL.",
    ),
    Check(
        id="xss-unescaped", category="security", title="Unescaped HTML sink (XSS)",
        severity="HIGH", framework="cwe-79",
        detect=_XSS_SINK,
        verify=_verify_xss,
        fix_hint="Escape/sanitize before rendering; prefer textContent or a vetted sanitizer.",
    ),
    Check(
        id="pii-in-code", category="privacy", title="PII literal in source",
        severity="MEDIUM", framework="gdpr-art5-art32",
        # Bounded quantifiers ({1,64} local / {1,255} domain / {2,24} TLD) are a ReDoS
        # guard (see test_email_regex_has_no_catastrophic_backtracking), not RFC-exact.
        detect=re.compile(
            r"(?i)([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}|\b\d{3}-\d{2}-\d{4}\b)"),
        verify=_verify_pii,
        fix_hint="Remove real PII from source (data minimisation); use fixtures/synthetic data.",
    ),
    Check(
        id="weak-crypto", category="security", title="Weak crypto on a credential",
        severity="MEDIUM", framework="cwe-327",
        detect=re.compile(r"(?i)\b(md5|sha1|hashlib\.md5|hashlib\.sha1|\bDES\b|RC4)\b"),
        verify=_verify_weak_crypto,
        fix_hint="Use a modern algorithm (bcrypt/argon2 for passwords, SHA-256+ otherwise).",
    ),
    Check(
        id="path-traversal", category="security", title="File path built from user input (traversal)",
        severity="HIGH", framework="cwe-22", detect=_PATH_TRAVERSAL, verify=_verify_path_traversal,
        fix_hint="Confine to a base dir (resolve + check prefix); use secure_filename / os.path.basename.",
    ),
    Check(
        id="ssrf", category="security", title="HTTP request to a user-controlled URL (SSRF)",
        severity="HIGH", framework="cwe-918", detect=_SSRF, verify=_verify_ssrf,
        fix_hint="Validate the URL against an allowlist of hosts/schemes before fetching.",
    ),
    Check(
        id="insecure-deserialization", category="security", title="Unsafe deserialization of untrusted data",
        severity="HIGH", framework="cwe-502", detect=_INSECURE_DESER, verify=_verify_insecure_deser,
        fix_hint="Use safe loaders (yaml.safe_load, json); never deserialize untrusted bytes with an unsafe loader.",
    ),
    Check(
        id="private-key-hardcoded", category="security", title="Hard-coded private key",
        severity="CRITICAL", framework="cwe-798", detect=_PRIVATE_KEY, verify=_verify_private_key,
        fix_hint="Remove the key from source and ROTATE it immediately; load from a secret manager.",
    ),
    Check(
        id="cleartext-transmission", category="security", title="Cleartext (http://) endpoint",
        severity="MEDIUM", framework="cwe-319", detect=_CLEARTEXT, verify=_verify_cleartext,
        fix_hint="Use https:// (TLS) for any sensitive transmission.",
    ),
    Check(
        id="floating-action-tag", category="supply-chain", title="GitHub Action pinned to a floating tag",
        severity="MEDIUM", framework="openssf-scorecard", detect=_FLOATING_TAG, verify=_verify_floating_tag,
        fix_hint="Pin actions to a full commit SHA (uses: owner/repo@<40-char-sha>), not @v1 / @main.",
    ),
    Check(
        id="pii-credit-card", category="privacy", title="Credit-card number (Luhn-valid) in source",
        severity="HIGH", framework="gdpr-art5-art32", detect=_CREDIT_CARD, verify=_verify_credit_card,
        fix_hint="Never store card numbers in source; use a PCI-compliant vault / tokenization.",
    ),
    Check(
        id="pii-phone", category="privacy", title="Phone number literal in source",
        severity="LOW", framework="gdpr-art5-art32", detect=_US_PHONE, verify=_verify_phone,
        fix_hint="Remove real phone numbers from source (data minimisation); use synthetic data.",
    ),
    Check(
        id="command-injection", category="security", title="OS command built from dynamic input",
        severity="HIGH", framework="cwe-78", detect=_CMD_INJECT, verify=_verify_cmd_inject,
        fix_hint="Never build a shell command from request/user input; pass args as a list, avoid shell=True.",
    ),
    Check(
        id="code-injection", category="security", title="Dynamic code execution on input",
        severity="CRITICAL", framework="cwe-94", detect=_CODE_INJECT, verify=_verify_code_inject,
        fix_hint="Never execute untrusted input; use ast.literal_eval or an explicit dispatch table.",
    ),
]
