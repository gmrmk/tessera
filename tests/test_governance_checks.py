"""Safety checks - tp (fires) / fp (verify drops it) / tn (clean) per check.

The two-signal gate is the load-bearing behavior: a candidate that detect flags
is dropped unless an INDEPENDENT verify confirms it. Each fp test proves a real
drop (placeholder secret, parameterized query, example email, plain checksum)."""
from __future__ import annotations

import pytest

from dual_log_engine.governance.safety.engine import scan_lines


def _ids(line: str) -> set[str]:
    return {f.check_id for f in scan_lines("f.py", [(1, line)])}


# --- secret-hardcoded ------------------------------------------------------- #

def test_secret_tp_real_key_fires():
    line = 'token = "' + ("sk-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5") + '"'
    assert "secret-hardcoded" in _ids(line)


def test_secret_fp_placeholder_dropped_by_verify():
    assert "secret-hardcoded" not in _ids('password = "your_password_here"')


def test_secret_tn_no_literal():
    assert "secret-hardcoded" not in _ids("api_key = os.environ['API_KEY']")


# --- sql-injection ---------------------------------------------------------- #

def test_sql_tp_interpolated_query_fires():
    line = "    return cur.execute(f\"SELECT * FROM t WHERE id = {" + "uid}\")"
    assert "sql-injection" in _ids(line)


def test_sql_fp_parameterized_dropped_by_verify():
    line = "    cur.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))"
    assert "sql-injection" not in _ids(line)


# --- xss-unescaped ---------------------------------------------------------- #

def test_xss_tp_variable_sink_fires():
    sink = "danger" + "ouslySetInner" + "HTML"
    line = "  return <div " + sink + "={{__html: userInput}} />"
    assert "xss-unescaped" in _ids(line)


def test_xss_fp_constant_dropped_by_verify():
    line = "  el.inner" + "HTML = " + '"static text"'
    assert "xss-unescaped" not in _ids(line)


# --- pii-in-code ------------------------------------------------------------ #

def test_pii_tp_real_email_fires():
    line = 'owner = "' + "jane.doe@acmecorp.com" + '"'
    assert "pii-in-code" in _ids(line)


def test_pii_fp_example_dropped_by_verify():
    line = 'contact = "' + "test@example.com" + '"'
    assert "pii-in-code" not in _ids(line)


# --- weak-crypto ------------------------------------------------------------ #

def test_weak_crypto_tp_on_credential_fires():
    assert "weak-crypto" in _ids("    digest = hashlib.md5(password.encode()).hexdigest()")


def test_weak_crypto_fp_checksum_dropped_by_verify():
    assert "weak-crypto" not in _ids("    cache_key = hashlib.md5(file_bytes).hexdigest()")


# --- grounding discipline --------------------------------------------------- #

def test_every_finding_is_grounded():
    line = 'token = "' + ("sk-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5") + '"'
    findings = scan_lines("f.py", [(1, line)])
    assert findings and all(f.framework and f.framework_url and f.clause for f in findings)


# --- enhancement-round checks (dangerous literals assembled from fragments) -- #

def test_path_traversal_tp_user_path_fires():
    assert "path-traversal" in _ids("    data = open(upload_dir + filename).read()")


def test_path_traversal_fp_sanitized_dropped():
    assert "path-traversal" not in _ids("    data = open(os.path.basename(upload_dir + filename)).read()")


def test_ssrf_tp_variable_url_fires():
    assert "ssrf" in _ids("    r = requests.get(user_url)")


def test_ssrf_fp_constant_url_dropped():
    assert "ssrf" not in _ids('    r = requests.get("https://api.internal/v1")')


def test_insecure_deser_tp_fires():
    line = "    obj = " + ("pic" + "kle") + ".loads(blob)"
    assert "insecure-deserialization" in _ids(line)


def test_insecure_deser_fp_safe_loader_dropped():
    assert "insecure-deserialization" not in _ids("    cfg = yaml.load(f, Loader=SafeLoader)")


def test_private_key_tp_fires():
    line = 'KEY = "-----BEGIN ' + "RSA PRIVATE" + ' KEY-----..."'
    assert "private-key-hardcoded" in _ids(line)


def test_private_key_fp_placeholder_dropped():
    line = "# -----BEGIN " + "PRIVATE" + " KEY----- (example placeholder)"
    assert "private-key-hardcoded" not in _ids(line)


def test_cleartext_tp_http_endpoint_fires():
    assert "cleartext-transmission" in _ids('    API = "http://api.internal.example/v1"')


def test_cleartext_fp_xml_namespace_dropped():
    assert "cleartext-transmission" not in _ids('    NS = "http://www.w3.org/2000/svg"')


def test_cleartext_tn_https():
    assert "cleartext-transmission" not in _ids('    API = "https://api.example.com"')


# --- E2: supply-chain + more PII -------------------------------------------- #

def test_floating_action_tag_tp_fires():
    assert "floating-action-tag" in _ids("  - uses: actions/checkout@v4")


def test_floating_action_tag_fp_sha_pinned_dropped():
    assert "floating-action-tag" not in _ids("  - uses: actions/checkout@" + ("a" * 40))


def test_credit_card_tp_luhn_valid_fires():
    assert "pii-credit-card" in _ids('card = "4242424242424242"')  # Luhn-valid test number


def test_credit_card_fp_luhn_invalid_dropped():
    assert "pii-credit-card" not in _ids('order_id = "1234567890123456"')  # fails the Luhn check


def test_phone_tp_fires():
    assert "pii-phone" in _ids('contact = "415-867-5309"')


def test_phone_fp_reserved_exchange_dropped():
    assert "pii-phone" not in _ids('support = "212-555-0199"')  # 555 exchange is fictional


def test_findings_carry_severity_and_fix_hint():
    line = 'token = "' + ("sk-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5") + '"'
    f = scan_lines("f.py", [(1, line)])[0]
    assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}  # SAF-4: severity classification
    assert f.fix_hint and len(f.fix_hint) > 5  # SAF-5: every finding carries a remediation hint


# --- SEC-1: command-injection + code-injection (purple-team PoCs) ----------- #

def test_command_injection_tp_dynamic():
    sysm = "sy" + "stem"
    assert "command-injection" in _ids('    os.' + sysm + '("ping " + host)')


def test_command_injection_fp_constant():
    sysm = "sy" + "stem"
    assert "command-injection" not in _ids('    os.' + sysm + '("uptime")')


def test_code_injection_tp_dynamic():
    fn = "ev" + "al"
    assert "code-injection" in _ids('    result = ' + fn + '(request.args["expr"])')


def test_code_injection_fp_literal():
    fn = "ev" + "al"
    assert "code-injection" not in _ids('    x = ' + fn + '("1 + 1")')


# --- SEC-3 / SEC-8: redaction overhaul + SEC-4: ReDoS guard (purple-team PoCs) ---

def test_redaction_covers_nonallowlist_keys_and_vendor_tokens():
    from dual_log_engine.governance.safety.engine import redact
    glpat = "glpat-" + "A" * 25
    out1 = redact('gitlab_token = "' + glpat + '"')
    assert "REDACTED" in out1 and glpat not in out1  # 'gitlab_token' was not in the old allowlist
    assert "REDACTED" in redact('db_password = "Sup3rS3cretValue!!"')  # nor was 'db_password'
    aiza = "AIza" + "B" * 35
    out2 = redact('cfg = "' + aiza + '"')
    assert "REDACTED" in out2 and aiza not in out2  # bare vendor token, no secret-ish key needed


def test_email_regex_has_no_catastrophic_backtracking():
    import time
    evil = "a" * 6000 + "@" + "a" * 6000 + "!"  # would hang an unbounded email regex
    t = time.perf_counter()
    scan_lines("f.py", [(1, evil)])
    assert time.perf_counter() - t < 1.0  # bounded regex + per-line cap -> fast


# --- SEC-8 detect side + SEC-3 entropy fallback (the over-marked-GREEN correction) ---

def test_secret_detect_covers_vendor_formats():
    # realistic varied tokens: a run of identical chars (or 'xxx') is correctly
    # dropped by the placeholder verify, so a credible test token must look real.
    charset = "AbCd3FgH5jKmNpQrStUvWyZ012789"  # no x/X (would hit the x{3,} placeholder), varied
    aiza = "AIza" + (charset * 2)[:35]
    assert "secret-hardcoded" in _ids('cfg = "' + aiza + '"')  # Google API key now flagged
    glpat = "glpat-" + (charset * 2)[:22]
    assert "secret-hardcoded" in _ids('tok = "' + glpat + '"')  # GitLab PAT now flagged


def test_secret_detect_drops_placeholder_vendor_token():
    assert "secret-hardcoded" not in _ids('cfg = "AIza' + ("x" * 35) + '"')  # fp: obvious placeholder


# --- SEC-2: SQLi via .format / % / executescript (purple-team PoCs) ---------- #

def test_sql_format_method_fires():
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM t WHERE id = {}".format(uid))')


def test_sql_percent_format_fires():
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM t WHERE id = %s" % uid)')


def test_sql_executescript_concat_fires():
    assert "sql-injection" in _ids('    cur.executescript("DROP TABLE " + name)')


def test_sql_like_pattern_not_flagged():
    assert "sql-injection" not in _ids("    cur.execute(\"SELECT * FROM t WHERE name LIKE '%abc%'\")")


# --- SEC-2 round-2: residual SQLi evasions found by the purple-team re-run ----- #

def test_sql_percent_no_space_fires():
    # round-2 #2 (HIGH FN): the no-whitespace %-operator must still flag
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM t WHERE n = %s"%name)')


def test_sql_fstring_uppercase_name_fires():
    # round-2 #3 (MED FN): an uppercase-initial / qualified f-string name must flag
    assert "sql-injection" in _ids('    cur.execute(f"SELECT * FROM t WHERE id = {ID}")')
    assert "sql-injection" in _ids('    cur.execute(f"SELECT * FROM t WHERE id = {User.id}")')


def test_sql_parameterized_like_tuple_not_flagged():
    # round-2 #4 (MED FP): concat inside the bind tuple must NOT flag a parameterized query
    assert "sql-injection" not in _ids('    cur.execute("SELECT * FROM t WHERE name LIKE %s", ("%" + q + "%",))')


def test_sql_adjacent_literal_interpolation_fires():
    # round-3 (HIGH regression): SQL split across implicitly-concatenated string literals
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM users " "WHERE id=%s" % uid)')
    assert "sql-injection" in _ids('    cur.execute(f"SELECT * FROM t WHERE id=" f"{uid}")')


def test_sql_constant_adjacent_literals_not_flagged():
    # the inverse: two CONSTANT adjacent literals (no var) must stay clean
    assert "sql-injection" not in _ids('    cur.execute("SELECT * FROM t " "WHERE active = 1")')


def test_sql_prefix_concat_then_interpolation_fires():
    # round-3 #2 (MED): a 'prefix + "...SELECT...%s" % var' previously defeated DETECT (the SQL
    # string did not immediately follow the call paren). Caught when a SQL keyword is in a literal;
    # if the keyword lives only in the prefix variable it is undetectable without dataflow.
    assert "sql-injection" in _ids('    cur.execute(prefix + "SELECT * FROM t WHERE id=%s" % uid)')
    assert "sql-injection" in _ids('    cur.execute(p + "INSERT INTO t VALUES (" + val + ")")')


def test_sql_uppercase_and_raw_fstring_prefix_fires():
    # round-4 (HIGH FN): F"" / rf"" / fR" prefixes building SQL from a var must ALL flag,
    # not just lowercase f"" (the prior fix only covered uppercase var names inside f"")
    for pre in ("F", "rf", "fR", "RF"):
        assert "sql-injection" in _ids('    cur.execute(' + pre + '"SELECT * FROM t WHERE id={uid}")'), pre


def test_sql_var_prefix_concat_fires():
    # round-5 (HIGH): a variable PREPENDED to the query (var + "SELECT...") must flag - detect
    # matched it but verify only checked string-then-var; now concat is confirmed either side
    assert "sql-injection" in _ids('    cur.execute(base + "SELECT * FROM t WHERE id=1")')
    assert "sql-injection" in _ids('    cur.execute(prefix + "DELETE FROM logs")')


def test_sql_percent_dict_and_format_map_fire():
    # round-5 (MED/LOW): inline %-dict and .format_map building SQL from a var must flag
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM t WHERE id=%(id)s" % {"id": uid})')
    assert "sql-injection" in _ids('    cur.execute("SELECT * FROM t WHERE id={id}".format_map(d))')


def test_entropy_redaction_masks_unprefixed_secret():
    from dual_log_engine.governance.safety.engine import redact
    # round-3: a 20+ char unprefixed high-entropy literal is masked (deliberate security bias -
    # masking a possible secret beats leaking one); a finding's evidence is check/file/line.
    sec = "Ab3Xy9Kp2Qr7Mn4Vw8Zt1Bc"  # 24 chars, mixed, no known prefix/key -> masked, not leaked
    out = redact('blob = "' + sec + '"')
    assert "<REDACTED>" in out and sec not in out
    assert "SELECT" in redact('q = "SELECT * FROM t WHERE id = 1"')  # SQL evidence (spaces) survives
    short = "Ab3Xy9Kp2Qr7"  # 12 chars, below the 20-char floor -> kept as evidence
    assert short in redact('val = "' + short + '"')


def test_redaction_masks_url_basic_auth_and_inline_password():
    # round-4 (MED): a credential embedded INSIDE a larger string (URL basic-auth, -p flag)
    # co-occurs with a firing check and must not reach the store in cleartext
    from dual_log_engine.governance.safety.engine import redact
    out = redact('clone("https://deploybot:hunter2SecretKeyAbc99@github.com/o/r")')
    assert "hunter2SecretKeyAbc99" not in out and "REDACTED" in out  # URL basic-auth password
    assert "Sup3rS3cretPwd99x" not in redact('run("psql --password=Sup3rS3cretPwd99x " + db)')  # explicit flag


def test_redaction_covers_query_and_bearer_but_not_ambiguous_p_flag():
    # round-6 (MED FP fix): query-param/oauth/bearer secrets masked; the OVERLOADED -p flag is
    # NOT touched, so docker ports / cp paths keep their evidence (the round-5 FP, now guarded)
    from dual_log_engine.governance.safety.engine import redact
    assert "Tok3nValueSecret99" not in redact('get("https://api.io/d?token=Tok3nValueSecret99")')
    assert "S3cr3tClientValue9" not in redact('get("https://api.io/x?client_secret=S3cr3tClientValue9")')
    assert "Bear3rT0kenSecretXyz" not in redact("h = 'Authorization: Bearer Bear3rT0kenSecretXyz'")
    assert "3306:3306" in redact('run("docker run -d mysql -p 3306:3306 --name db")')  # port, not a secret
    assert "8080" in redact('run("docker run -p8080:80 img")')
    assert "/etc/my.cnf" in redact('run("mysql; cp -p /etc/my.cnf /backup/")')  # path, not a secret


def test_redaction_empty_user_url_and_bare_password_flag():
    # round-7: ://:pw@ (empty user) masks; bare --password (interactive prompt, no inline value)
    # must NOT eat the next token, while the --password= form still masks
    from dual_log_engine.governance.safety.engine import redact
    assert "S3cretRedisPass99" not in redact('r = "redis://:S3cretRedisPass99@localhost:6379"')
    assert "--verbose" in redact('run("pg_dump --password --verbose mydb")')   # bare flag: next token kept
    assert "Re4lSecretPw99" not in redact('run("psql --password=Re4lSecretPw99 db")')  # = form still masks


# --- census detect slice: PII (RFC2606 + SSN), recall, FP, Unicode, defang ----- #

def test_pii_fp_rfc2606_reserved_domain_dropped():
    # n=21: an address in an RFC2606/RFC6761 documentation domain is never real PII.
    assert "pii-in-code" not in _ids('owner = "' + "someone@mycompany.test" + '"')
    assert "pii-in-code" not in _ids('owner = "' + "dev@corp.invalid" + '"')
    assert "pii-in-code" not in _ids('owner = "' + "a@sub.example.org" + '"')


def test_pii_ssn_tp_real_shape_fires():
    # n=23: an SSN-shaped literal with a structurally-valid area/group/serial fires.
    assert "pii-in-code" in _ids('ssn = "' + "123-45-6789" + '"')


def test_pii_ssn_fp_invalid_area_dropped():
    # n=23: never-issued SSN blocks (area 000/666/900-999, group 00, serial 0000) are refuted.
    assert "pii-in-code" not in _ids('ssn = "' + "000-12-3456" + '"')
    assert "pii-in-code" not in _ids('ssn = "' + "666-12-3456" + '"')
    assert "pii-in-code" not in _ids('ssn = "' + "900-12-3456" + '"')
    assert "pii-in-code" not in _ids('ssn = "' + "123-00-6789" + '"')
    assert "pii-in-code" not in _ids('ssn = "' + "123-45-0000" + '"')


def test_weak_crypto_tp_pw_named_var_fires():
    # n=25: a credential named with the pw/pwd synonym now supplies the _SEC_CTX signal.
    assert "weak-crypto" in _ids("    h = hashlib.md5(pw).hexdigest()")
    assert "weak-crypto" in _ids("    h = hashlib.md5(pwd).hexdigest()")


def test_cleartext_fp_rfc1918_private_host_dropped():
    # n=36: cleartext http to a loopback / RFC1918 / link-local host is not a sensitive-transmission FP.
    assert "cleartext-transmission" not in _ids('    API = "http://192.168.1.1/health"')
    assert "cleartext-transmission" not in _ids('    API = "http://10.0.0.5/metrics"')
    assert "cleartext-transmission" not in _ids('    API = "http://172.16.0.1/status"')
    assert "cleartext-transmission" not in _ids('    API = "http://169.254.1.1/"')
    # and a genuinely external cleartext endpoint still fires
    assert "cleartext-transmission" in _ids('    API = "http://api.internal.example/v1"')


def test_floating_action_tag_fp_sha256_pin_dropped():
    # n=37: a 64-hex (SHA-256) commit pin is treated as pinned, not floating.
    assert "floating-action-tag" not in _ids("  - uses: actions/checkout@" + ("a" * 64))
    # and a short SHA (>=7 hex) is also accepted as pinned
    assert "floating-action-tag" not in _ids("  - uses: actions/checkout@" + ("abc1234"))


def test_floating_action_tag_handles_trailing_comment_with_at():
    # MED: verify must read the ref from the DETECT match's @<ref> token, not rsplit the WHOLE
    # line on '@'. A trailing comment that itself contains '@' otherwise hijacks the rsplit and
    # makes verify inspect the wrong token (a real floating tag read as a pinned SHA -> FN).
    floating = "  - uses: actions/checkout@v4  # see actions/checkout@" + ("a" * 40)
    assert "floating-action-tag" in _ids(floating)  # the USED ref is v4 (floating) -> flagged
    # inverse: a real 40-hex pin whose comment contains a floating @v1 must NOT be flagged
    pinned = "  - uses: actions/checkout@" + ("a" * 40) + "  # was @v1"
    assert "floating-action-tag" not in _ids(pinned)  # the USED ref is the SHA -> not flagged


def test_credit_card_unicode_digit_does_not_corrupt_luhn():
    # n=39: a Unicode decimal digit must never reach ord()-48 inside the Luhn check. The
    # ASCII-only strip drops it, leaving the 15 ASCII digits (which ARE Luhn-valid) -> fires.
    # Under the old non-ASCII strip the Unicode digit was kept and corrupted the Luhn total.
    arabic_indic_four = "\u0664"  # Arabic-Indic 4; written as an escape to keep source ASCII-only
    card = "424242424242424" + arabic_indic_four  # 15 ASCII (Luhn-valid) + 1 Unicode digit = 16
    assert "pii-credit-card" in _ids('card = "' + card + '"')


def test_checks_source_does_not_self_flag_defanged_literals():
    # n=20 / n=49: dogfood the scanner on checks.py's own source and assert the assembled
    # (de-fragmented) dangerous literals - the XSS sink, the unsafe-deserialization module
    # name, the PEM private-key header, the dynamic-exec sinks, the os shell sinks - never
    # produce a self-finding. A future de-fragmentation that reassembled a contiguous
    # literal would break this invariant.
    from pathlib import Path
    import dual_log_engine.governance.safety.checks as checks_mod
    src = Path(checks_mod.__file__).read_text(encoding="utf-8").splitlines()
    ids = {f.check_id for f in scan_lines("checks.py", [(i + 1, t) for i, t in enumerate(src)])}
    for defanged in (
        "xss-unescaped", "insecure-deserialization", "private-key-hardcoded",
        "code-injection", "command-injection",
    ):
        assert defanged not in ids, defanged


def test_redaction_masks_multiple_secret_classes_on_one_line():
    # n=75: order-independence of the sequential redaction passes - an AKIA token, a
    # key='value' assignment secret, and a Bearer token on ONE line are all masked.
    from dual_log_engine.governance.safety.engine import redact
    akia = "AKIA" + "B" * 16
    bearer_val = "Bear3rT0kenSecretXyz"
    assign_secret = "Sup3rS3cretAssignVal"
    line = 'cfg("' + akia + '", api_key="' + assign_secret + '", "Bearer ' + bearer_val + '")'
    out = redact(line)
    assert akia not in out
    assert assign_secret not in out
    assert bearer_val not in out
    assert "REDACTED" in out


def test_redaction_masks_jwt_form_token():
    # n=354: pins the JWT prefix claim (SECURITY-HARDENING.md / engine.py _REDACT_TOKEN).
    from dual_log_engine.governance.safety.engine import redact
    jwt = "eyJhbGciOiJIUzI1NiInd" + ".eyJzdWIiOiIxMjM0NTY3ODkw" + ".SflKxwRJSMeKKF2QT4fwpM"
    out = redact('auth = "' + jwt + '"')
    assert jwt not in out and "REDACTED" in out


def test_ungrounded_check_raises_keyerror():
    # n=352: SAF-2 'no source, no finding' - a check citing an unknown framework id raises
    # KeyError through cite() (engine.py / grounding.cite), so it cannot silently ship.
    import re as _re
    from dual_log_engine.governance.safety.checks import Check
    import dual_log_engine.governance.safety.engine as eng
    stub = Check(
        id="stub-ungrounded", category="security", title="stub", severity="LOW",
        framework="no-such-framework-id", detect=_re.compile("ALWAYSMATCHME"),
        verify=lambda line, m: True, fix_hint="n/a",
    )
    original = list(eng.CHECKS)
    eng.CHECKS.append(stub)
    try:
        with pytest.raises(KeyError):
            scan_lines("f.py", [(1, "ALWAYSMATCHME")])
    finally:
        eng.CHECKS[:] = original


@pytest.mark.xfail(reason="single-line lexical detection, not dataflow: a SQL/URL/code "
                          "string built by concatenation is undetectable without taint analysis",
                   strict=True)
def test_known_dataflow_limit_concatenated_sinks_are_false_negatives():
    # n=53: documents the known FN class. requests.get of a concatenated URL is refuted as a
    # 'constant URL literal' (verify sees the leading quote), and dynamic code execution of a
    # concatenated string is refuted as 'exec of a literal constant' - both real dataflow
    # limits, marked xfail so a future taint-aware upgrade flips this to xpass.
    fn = "ex" + "ec"
    assert "ssrf" in _ids('    r = requests.get("http://" + host)')
    assert "code-injection" in _ids("    " + fn + '("x" + y)')
