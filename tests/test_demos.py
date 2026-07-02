"""Runnable self-check demos - the README-documented quickstart entry points run green.

    python -m dual_log_engine.demo               # heritage engine end-to-end self-check
    python -m dual_log_engine.governance.demo    # governance end-to-end self-check

Both mains self-assert internally (every plan invariant is an ``assert``) and print
"ALL CHECKS PASSED"; a broken invariant is a non-zero exit. Executing them here keeps
these documented, user-facing entry points from silently rotting - e.g. an honesty-language
edit to the report wording that the governance demo asserts against - without the suite
going red. Run in a subprocess so a demo's own ``sys.exit`` / global state cannot leak in.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest


def _run_module(module: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", module],
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)


@pytest.mark.slow
def test_engine_demo_runs_green(tmp_path):
    # ENG/heritage self-check: ingest -> evict -> distill -> graph -> query -> audit.
    env = dict(os.environ)
    env["DLE_MEMORY_DIR"] = str(tmp_path / "mem")  # keep the demo's writes out of the repo
    env["DLE_LLM"] = "mock"  # an ambient DLE_LLM=anthropic would turn this hermetic check into a real API call
    r = _run_module("dual_log_engine.demo", env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL CHECKS PASSED" in r.stdout


@pytest.mark.slow
def test_governance_demo_runs_green_keyless(tmp_path):
    # Governance self-check in the DEFAULT keyless mode (no DLE_CHAIN_KEY): the report
    # wording forks signed-vs-keyless, so this guards the demo's integrity-line assertion
    # against the honesty-language edits that keep rewording report.py.
    env = dict(os.environ)
    env.pop("DLE_CHAIN_KEY", None)
    env.pop("DLE_CHAIN_KEY_FILE", None)
    r = _run_module("dual_log_engine.governance.demo", env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL CHECKS PASSED" in r.stdout


@pytest.mark.slow
def test_governance_demo_runs_green_signed(tmp_path):
    # The same self-check with an out-of-DB HMAC key set -> signed integrity line.
    env = dict(os.environ)
    env["DLE_CHAIN_KEY"] = "demo-self-check-key-1234567890"
    r = _run_module("dual_log_engine.governance.demo", env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL CHECKS PASSED" in r.stdout
