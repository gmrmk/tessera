"""Engine integration surfaces - daemon, MCP server, and capture hooks load + wire to the engine.

These are thin surfaces over MemoryEngine (whose logic is covered by test_engine.py);
here we prove the surfaces themselves load and expose their entry points (ENG-8/9/10)."""
from __future__ import annotations

import asyncio
import io
import os
import py_compile
import subprocess
import sys
from pathlib import Path

import pytest

import dual_log_engine.daemon as daemon

HOOKS_DIR = Path(__file__).resolve().parents[1] / "hooks"
_BOM = chr(0xFEFF)  # U+FEFF assembled from a code point so this source stays ASCII-only


def test_daemon_entrypoint_exists():
    assert callable(daemon.run)  # ENG-8: dle-serve console-script target


def test_mcp_server_entrypoint_exists():
    pytest.importorskip("mcp")  # the [mcp] extra
    import dual_log_engine.mcp_server as mcp
    assert callable(mcp.run)  # ENG-9: dle-mcp console-script target


def test_capture_hooks_are_valid_python():
    scripts = sorted(HOOKS_DIR.glob("*.py"))
    assert scripts, "no hook scripts found"
    for s in scripts:
        py_compile.compile(str(s), doraise=True)  # ENG-10: every capture/inject hook compiles


def test_networkx_not_imported_on_governance_hot_path():
    # ENG-1: pins the "networkx-free hot path" claim - importing the package and running a
    # governance scan (the documented hot path) must NOT pull networkx, which is lazily
    # imported only by the heritage graph store. Run in a fresh subprocess so test-order
    # import pollution from other tests cannot mask a regression.
    code = (
        "import sys\n"
        "import dual_log_engine\n"
        "from dual_log_engine.governance.safety.engine import scan_lines\n"
        "scan_lines('f.py', [(1, 'api_key = \"x\"')])\n"
        "assert 'networkx' not in sys.modules, sorted(m for m in sys.modules if 'networkx' in m)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


# --- ENG-8: dle-serve daemon per-tick behavior ------------------------------ #

class _FakeEngine:
    """Minimal stand-in exposing only what _loop touches: distill_due()."""
    def __init__(self, *, raises: bool = False) -> None:
        self.calls = 0
        self.raises = raises

    async def distill_due(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("boom in a tick")
        return {"groups": 0, "distilled": 0}


def _stop_sleep_after(n: int, monkeypatch):
    """Patch the daemon's asyncio.sleep to end the loop after n ticks (CancelledError
    is a BaseException, so _loop's `except Exception` cannot swallow it)."""
    ticks = {"seen": 0}

    async def fake_sleep(_interval):
        ticks["seen"] += 1
        if ticks["seen"] >= n:
            raise asyncio.CancelledError
    monkeypatch.setattr(daemon.asyncio, "sleep", fake_sleep)


def test_daemon_loop_distills_each_tick(monkeypatch):
    engine = _FakeEngine()
    _stop_sleep_after(1, monkeypatch)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(daemon._loop(engine, 0.01))
    assert engine.calls == 1  # distill_due awaited on the tick


def test_daemon_loop_survives_a_tick_error(monkeypatch, capsys):
    # A raised exception in one tick is caught and logged; the loop keeps running
    # (fail-soft) rather than dying, so distill_due is still called on the next tick.
    engine = _FakeEngine(raises=True)
    _stop_sleep_after(2, monkeypatch)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(daemon._loop(engine, 0.01))
    assert engine.calls == 2  # loop continued past the first tick's error
    assert "[dle-serve] tick error" in capsys.readouterr().err


# --- ENG-9: MCP tool functions -------------------------------------------- #

def test_mcp_tools_ingest_and_query(monkeypatch, tmp_path):
    pytest.importorskip("mcp")
    import dual_log_engine.mcp_server as mcp
    from dual_log_engine.engine import MemoryEngine
    monkeypatch.setattr(mcp, "_engine", MemoryEngine(root=str(tmp_path / "mem")))

    assert mcp.memory_ingest("t", "r", "run", "hello world") == {"buffered": 1}

    with pytest.raises(ValueError):  # unknown mode is rejected, not silently coerced
        asyncio.run(mcp.memory_query("t", "r", "q", mode="bogus"))

    out = asyncio.run(mcp.memory_query("t", "r", "q", mode="hybrid"))  # case-insensitive
    assert set(out) == {"mode", "entities", "relations", "prompt", "token_estimate"}
    assert out["mode"] == "HYBRID"


# --- ENG-10: capture/inject hook helpers ---------------------------------- #

@pytest.fixture()
def hook_common(monkeypatch):
    monkeypatch.syspath_prepend(str(HOOKS_DIR))
    import _common  # imported from the hooks dir on the patched path
    return _common


def test_hook_read_payload_tolerates_bom_and_garbage(hook_common, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(_BOM + "not json {{{"))
    assert hook_common.read_payload() == {}  # malformed (even with a BOM) -> empty, never raises
    monkeypatch.setattr("sys.stdin", io.StringIO('{"session_id": "S1"}'))
    assert hook_common.read_payload() == {"session_id": "S1"}


def test_hook_resolve_ids_env_then_payload(hook_common, monkeypatch):
    monkeypatch.setenv("DLE_TENANT_ID", "acme")
    monkeypatch.setenv("DLE_REPO_ID", "myrepo")
    tenant, repo, run = hook_common.resolve_ids({"session_id": "S1"})
    assert (tenant, repo, run) == ("acme", "myrepo", "S1")
    # payload session_id wins for the run id; repo falls back to the cwd name with no env.
    monkeypatch.delenv("DLE_REPO_ID", raising=False)
    _t, repo2, run2 = hook_common.resolve_ids({"cwd": "/tmp/proj-x", "session_id": "S2"})
    assert repo2 == "proj-x" and run2 == "S2"


def _run_hook(script: str, stdin: str, tmp_path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["DLE_MEMORY_DIR"] = str(tmp_path / "mem")  # isolate the store from the repo
    return subprocess.run(
        [sys.executable, str(HOOKS_DIR / script)],
        input=stdin, capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)


def test_inject_hook_suppresses_empty_context(tmp_path):
    # The bullet guard ("\n- " must be present): with an empty store the rendered context
    # has no entity/relation bullet, so the SessionStart hook injects NOTHING (and exits 0).
    r = _run_hook("session_start_inject.py", "", tmp_path)
    assert r.returncode == 0
    assert "additionalContext" not in r.stdout


def test_inject_hook_fail_silent_on_garbage_stdin(tmp_path):
    # Garbage (non-JSON, BOM-prefixed) stdin must never crash a hook: read_payload -> {}, exit 0.
    r = _run_hook("session_start_inject.py", _BOM + "not json at all {{{", tmp_path)
    assert r.returncode == 0
    assert "additionalContext" not in r.stdout
