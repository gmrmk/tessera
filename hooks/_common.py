"""Shared helpers for the dual-log-memory context-injection hooks.

Every hook is defensive and fail-silent: a hook must never block or crash a
Claude Code session. If the engine can't be imported or anything throws, the
hook simply injects/ingests nothing and exits 0.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_BOM = chr(0xFEFF)  # U+FEFF built from a code point so this source has no BOM byte


def ensure_import() -> bool:
    """Make ``dual_log_engine`` importable (installed, or via the sibling src/)."""
    try:
        import dual_log_engine  # noqa: F401
        return True
    except ImportError:
        src = Path(__file__).resolve().parents[1] / "src"
        if src.is_dir():
            sys.path.insert(0, str(src))
        try:
            import dual_log_engine  # noqa: F401
            return True
        except ImportError:
            return False


def read_payload() -> dict:
    """Read the Claude Code hook payload (JSON) from stdin, tolerating BOM/garbage."""
    raw = sys.stdin.read()
    if not raw:
        return {}
    raw = raw.lstrip(_BOM)  # tolerate a leading UTF-8 BOM
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def resolve_ids(payload: dict) -> tuple[str, str, str]:
    """Resolve (tenant_id, repo_id, agent_run_id) from env, then the payload.

    Defaults keep the hooks usable with zero configuration: tenant ``local``,
    repo = the working-directory name, run = the Claude Code session id.
    """
    cwd = payload.get("cwd") or os.getcwd()
    tenant = os.environ.get("DLE_TENANT_ID", "local")
    repo = os.environ.get("DLE_REPO_ID") or Path(cwd).name or "default"
    run = payload.get("session_id") or os.environ.get("DLE_AGENT_RUN_ID") or "session"
    return tenant, repo, run


def memory_dir(payload: dict) -> str:
    """Where the shared store lives. Defaults to ``<cwd>/.memory`` (per-project)."""
    explicit = os.environ.get("DLE_MEMORY_DIR")
    if explicit:
        return explicit
    cwd = payload.get("cwd") or os.getcwd()
    return str(Path(cwd) / ".memory")


def make_engine(payload: dict):
    from dual_log_engine.engine import MemoryEngine

    return MemoryEngine(root=memory_dir(payload))


def emit_additional_context(event_name: str, text: str, limit: int = 4000) -> None:
    """Emit a Claude Code hook result that injects ``text`` as added context."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": text[:limit],
        }
    }))
