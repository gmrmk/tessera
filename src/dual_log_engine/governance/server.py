"""server.py - a stdlib HTTP webhook so an org's CI can feed changes in.

No third-party deps (http.server only). Endpoints:

  POST /ingest      body {org, repo, diff, author?, agent?, sha?} -> findings JSON
  GET  /healthz     -> {"ok": true}
  GET  /dashboard?org=ORG    -> HTML dashboard
  GET  /report?org=ORG       -> text report
  GET  /compliance?org=ORG   -> text compliance posture

Auth is a minimal shared-token stub, OFF by default: if DLE_GOV_TOKEN is set,
every request must send a matching `X-DLE-Token` header (else 401). Run this
behind TLS in production; the SQLite file IS the tamper-evident audit trail, so
back it up and treat it as the system of record.

Agent-agnostic by construction: it ingests a diff + attribution, so any agent
(or human) CI can call it.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .chain import GovernanceChain
from .compliance import compliance_report
from .dashboard import render_dashboard
from .ingest import Attribution, ingest_change
from .report import org_report
from .store import GovernanceStore

DEFAULT_DB = os.environ.get("DLE_GOV_DB", ".governance/governance.db")
# Cap a single diff payload to bound per-request memory (a CI feeds one change
# at a time; large repos should pre-split). Sits behind the documented front
# proxy, which normalizes request framing.
MAX_BODY = 5 * 1024 * 1024  # 5 MB


def _blank(s: str) -> bool:
    """True if a string has no visible character (empty, whitespace-only, or only
    zero-width/BOM/control chars) - the SAME condition store._tenant_key rejects, so the
    HTTP edge and the store never disagree about which inputs are 'blank' (which is how a
    .strip()-only edge check let invisible chars 500 deep inside the store)."""
    return not any(ch.isprintable() and not ch.isspace() for ch in s)


class _GovHandler(BaseHTTPRequestHandler):
    server_version = "dle-govern"  # no version: avoids fingerprinting + a stale 1.0-vs-0.1.0 banner
    sys_version = ""  # don't leak the Python build in the Server: header

    # --- helpers ------------------------------------------------------------ #
    @property
    def _cfg(self) -> dict:
        return self.server.dle_cfg  # type: ignore[attr-defined]

    def _auth_ok(self) -> bool:
        token = self._cfg.get("token")
        if not token:
            return True  # auth off by default
        # Constant-time compare so a timing side-channel can't reveal the shared token.
        return hmac.compare_digest(str(self.headers.get("X-DLE-Token") or ""), str(token))

    def _open(self):
        store = GovernanceStore(self._cfg["db"])
        return store, GovernanceChain(store)

    def _send(self, code: int, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
        else:
            payload = str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # quiet by default; CI captures stdout if it wants
        pass

    # --- routes ------------------------------------------------------------- #
    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        u = urlparse(self.path)
        org = (parse_qs(u.query).get("org") or [""])[0]
        if u.path == "/healthz":
            return self._send(200, {"ok": True, "service": "dle-govern"})
        if u.path not in ("/dashboard", "/report", "/compliance"):
            return self._send(404, {"error": "not found"})
        if _blank(org):  # reject empty/whitespace/zero-width org at the edge (do_GET had no guard)
            return self._send(400, {"error": "missing or invalid ?org="})
        try:
            store, chain = self._open()
            if u.path == "/dashboard":
                return self._send(200, render_dashboard(store, chain, org), "text/html")
            if u.path == "/report":
                return self._send(200, org_report(store, chain, org), "text/plain")
            return self._send(200, compliance_report(store, chain, org), "text/plain")
        except ValueError as exc:  # a tenant-key rejection is bad input -> 400, never a crashed thread
            return self._send(400, {"error": "invalid org", "detail": str(exc)})
        except Exception as exc:  # mirror do_POST: never crash the worker thread or leak a trace
            print(f"do_GET failed: {type(exc).__name__}", file=sys.stderr)
            return self._send(500, {"error": "request failed"})

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        if urlparse(self.path).path != "/ingest":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (ValueError, TypeError):  # a bad header is not bad JSON; name it honestly
            return self._send(400, {"error": "invalid Content-Length"})
        if length < 0:  # a negative length parses as int but rfile.read(-1) blocks the worker
            return self._send(400, {"error": "invalid Content-Length"})
        if length > MAX_BODY:
            return self._send(413, {"error": "payload too large"})
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            return self._send(400, {"error": "invalid JSON body"})

        if not isinstance(data, dict):
            return self._send(400, {"error": "body must be a JSON object"})
        missing = [k for k in ("org", "repo", "diff") if data.get(k) in (None, "")]
        if missing:  # presence, not truthiness, so a numeric 0 isn't mislabelled "missing"
            return self._send(400, {"error": f"missing fields: {', '.join(missing)}"})
        non_str = [k for k in ("org", "repo", "diff") if not isinstance(data.get(k), str)]
        if non_str:  # a non-string (incl. numeric) field would crash parse_diff / be ambiguous
            return self._send(400, {"error": f"fields must be strings: {', '.join(non_str)}"})
        blank = [k for k in ("org", "repo") if _blank(data[k])]
        if blank:  # empty/whitespace/zero-width tenant or repo would 500 in _tenant_key; reject here
            return self._send(400, {"error": f"fields must be non-empty + visible: {', '.join(blank)}"})

        store, chain = self._open()
        attr = Attribution(author=str(data.get("author") or "unknown"), agent=str(data.get("agent") or "human"))
        try:
            res = ingest_change(store, chain, data["org"], data["repo"], data["diff"], attr, sha=data.get("sha"))
        except ValueError as exc:  # bad input that slipped the edge checks -> 400, not 500
            return self._send(400, {"error": "invalid input", "detail": str(exc)})
        except Exception as exc:  # never leak a stack trace, exc class, or hang the worker
            print(f"ingest failed: {type(exc).__name__}", file=sys.stderr)  # type stays in the server log, not on the wire
            return self._send(500, {"error": "ingest failed"})
        return self._send(200, {
            "change_id": res["change_id"],
            "n_findings": res["n_findings"],
            "chain_seq": res["chain_seq"],
            "files": res["files"],
            "findings": [
                {"check_id": f.check_id, "severity": f.severity, "file": f.file,
                 "line": f.line, "framework": f.framework}
                for f in res["findings"]
            ],
        })


def make_server(db=DEFAULT_DB, token=None, host="127.0.0.1", port=0) -> ThreadingHTTPServer:
    """Build (do not start) the server. port=0 picks an ephemeral port (tests)."""
    srv = ThreadingHTTPServer((host, port), _GovHandler)
    srv.dle_cfg = {"db": str(db), "token": token}  # type: ignore[attr-defined]
    return srv


def run() -> None:
    """Console-script / module entry point (serves forever)."""
    host = os.environ.get("DLE_GOV_HOST", "127.0.0.1")
    port = int(os.environ.get("DLE_GOV_PORT", "8765"))
    token = os.environ.get("DLE_GOV_TOKEN") or None
    srv = make_server(db=DEFAULT_DB, token=token, host=host, port=port)
    print(f"dle-govern serving on http://{host}:{port}  (auth {'ON' if token else 'OFF'}, db={DEFAULT_DB})",
          file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("dle-govern stopped", file=sys.stderr)


if __name__ == "__main__":
    run()
