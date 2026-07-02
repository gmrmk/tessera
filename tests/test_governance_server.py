"""Webhook server - real HTTP integration on an ephemeral port (no third-party deps)."""
from __future__ import annotations

import http.client
import json
import tempfile
import threading
from pathlib import Path

from _govfixtures import DIRTY

from dual_log_engine.governance.server import make_server


def _serve(token=None):
    db = Path(tempfile.mkdtemp(prefix="dle-srv-")) / "g.db"
    srv = make_server(db=db, token=token, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = dict(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body)
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=h)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    conn.close()
    return resp.status, data


def test_healthz_ok():
    srv, port = _serve()
    try:
        st, body = _req(port, "GET", "/healthz")
        assert st == 200 and json.loads(body)["ok"] is True
    finally:
        srv.shutdown()


def test_ingest_returns_findings():
    srv, port = _serve()
    try:
        st, body = _req(port, "POST", "/ingest",
                        {"org": "acme", "repo": "api", "diff": DIRTY, "agent": "claude"})
        assert st == 200, body
        d = json.loads(body)
        ids = {f["check_id"] for f in d["findings"]}
        assert "secret-hardcoded" in ids and "sql-injection" in ids
        assert d["n_findings"] >= 2 and d["chain_seq"] == 1
    finally:
        srv.shutdown()


def test_ingest_missing_fields_400():
    srv, port = _serve()
    try:
        st, _ = _req(port, "POST", "/ingest", {"org": "acme"})  # missing repo + diff
        assert st == 400
    finally:
        srv.shutdown()


def test_auth_enforced_when_token_set():
    srv, port = _serve(token="s3cr3t")
    try:
        assert _req(port, "GET", "/healthz")[0] == 401                                  # no token
        assert _req(port, "GET", "/healthz", headers={"X-DLE-Token": "wrong"})[0] == 401  # bad token
        assert _req(port, "GET", "/healthz", headers={"X-DLE-Token": "s3cr3t"})[0] == 200  # good token
    finally:
        srv.shutdown()


def test_dashboard_endpoint_serves_html():
    srv, port = _serve()
    try:
        _req(port, "POST", "/ingest", {"org": "acme", "repo": "api", "diff": DIRTY, "agent": "claude"})
        st, body = _req(port, "GET", "/dashboard?org=acme")
        assert st == 200 and "<!doctype html>" in body and "acme" in body
    finally:
        srv.shutdown()


def test_unknown_route_404():
    srv, port = _serve()
    try:
        assert _req(port, "GET", "/nope")[0] == 404
    finally:
        srv.shutdown()


# --- SEC-9: input validation + banner leak (purple-team) -------------------- #

def test_ingest_nonstring_diff_rejected_400():
    srv, port = _serve()
    try:
        st, _ = _req(port, "POST", "/ingest", {"org": "acme", "repo": "api", "diff": 123})
        assert st == 400  # a non-string diff would crash parse_diff -> rejected, not 500/hang
    finally:
        srv.shutdown()


def test_ingest_nonobject_body_rejected_400():
    srv, port = _serve()
    try:
        st, _ = _req(port, "POST", "/ingest", [1, 2, 3])  # JSON array, not an object
        assert st == 400
    finally:
        srv.shutdown()


def test_server_header_does_not_leak_python_build():
    srv, port = _serve()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        server = resp.getheader("Server") or ""
        conn.close()
        assert "Python" not in server  # sys_version blanked
        assert "dle-govern" in server  # our own service version still identifies it
    finally:
        srv.shutdown()


# --- SEC-9 round-2: validation gaps found by the purple-team re-run ----------- #

def test_ingest_whitespace_org_is_400_not_500():
    # round-2 #5 (HIGH): a whitespace-only org must be a clean 400, not a 500 from deep inside
    srv, port = _serve()
    try:
        st, _ = _req(port, "POST", "/ingest", {"org": "   ", "repo": "api", "diff": "x"})
        assert st == 400
    finally:
        srv.shutdown()


def test_ingest_numeric_org_gets_clear_message_not_missing():
    # round-2 #6 (MED): a numeric org is rejected as "must be strings", not mislabelled "missing"
    srv, port = _serve()
    try:
        st, body = _req(port, "POST", "/ingest", {"org": 0, "repo": "api", "diff": "x"})
        assert st == 400 and "string" in body.lower() and "missing" not in body.lower()
    finally:
        srv.shutdown()


def test_ingest_control_and_zero_width_org_is_400_not_500():
    # round-3 (HIGH): control / zero-width org/repo must be 400 at the edge, not 500 from _tenant_key
    srv, port = _serve()
    try:
        assert _req(port, "POST", "/ingest", {"org": "\x00", "repo": "api", "diff": "x"})[0] == 400
        assert _req(port, "POST", "/ingest", {"org": "\u200b", "repo": "api", "diff": "x"})[0] == 400
        assert _req(port, "POST", "/ingest", {"org": "acme", "repo": "\u200b", "diff": "x"})[0] == 400
    finally:
        srv.shutdown()


def test_get_invisible_org_is_400_not_crash():
    # round-3 (HIGH): do_GET had no guard -> a whitespace/zero-width org crashed the handler thread
    srv, port = _serve()
    try:
        assert _req(port, "GET", "/report?org=%20%20%20")[0] == 400      # whitespace-only
        assert _req(port, "GET", "/dashboard?org=%E2%80%8B")[0] == 400   # zero-width space (utf-8)
    finally:
        srv.shutdown()


# --- IFC-7: body-size + Content-Length framing -------------------------------- #

def test_ingest_oversize_body_413():
    # server.py MAX_BODY caps a single diff payload; an over-cap POST is 413, not 500.
    from dual_log_engine.governance.server import MAX_BODY
    srv, port = _serve()
    try:
        # Advertise an over-cap Content-Length; the server must 413 from the header
        # BEFORE reading the body (so a tiny actual body keeps the test deterministic).
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/ingest", skip_host=False, skip_accept_encoding=True)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(MAX_BODY + 1))
        conn.endheaders()
        conn.send(b"{}")  # body shorter than the advertised length; server 413s before reading it
        resp = conn.getresponse()
        st = resp.status
        resp.read()
        conn.close()
        assert st == 413
    finally:
        srv.shutdown()


def test_ingest_bad_content_length_is_its_own_400():
    # A non-numeric Content-Length is a bad header, not bad JSON -> dedicated message.
    srv, port = _serve()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/ingest")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "not-a-number")
        conn.endheaders()
        conn.send(b"{}")
        resp = conn.getresponse()
        st = resp.status
        body = resp.read().decode("utf-8")
        conn.close()
        assert st == 400 and "content-length" in body.lower()
    finally:
        srv.shutdown()


def test_ingest_negative_content_length_is_400_not_hang():
    # A NEGATIVE Content-Length parses as int and would reach rfile.read(-1), which blocks the
    # worker. It must be rejected as an invalid Content-Length 400 BEFORE any read (timeout=5
    # makes a regression surface as a hang/timeout, not a pass).
    srv, port = _serve()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/ingest", skip_host=False, skip_accept_encoding=True)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "-1")
        conn.endheaders()
        conn.send(b"{}")
        resp = conn.getresponse()
        st = resp.status
        body = resp.read().decode("utf-8")
        conn.close()
        assert st == 400 and "content-length" in body.lower()
    finally:
        srv.shutdown()
