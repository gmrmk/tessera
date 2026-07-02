"""AuditWriter  -  writes the record, and fails silently rather than blocking."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from dual_log_engine.audit import AuditWriter
from dual_log_engine.clients import TokenUsage


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="dle-audit-")) / ".memory" / "traces"


def test_write_creates_json_with_expected_fields():
    base = _tmp_dir()
    audit = AuditWriter(base_dir=base)
    path = asyncio.run(audit.write(
        tenant_id="acme", repo_id="api", agent_run_id="run-1",
        prompt="PROMPT", context_snippets={"entities": [], "relations": []},
        usage=TokenUsage(input_tokens=10, output_tokens=5)))
    assert path is not None and path.exists()
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["tenant_id"] == "acme" and doc["repo_id"] == "api" and doc["agent_run_id"] == "run-1"
    assert doc["prompt"] == "PROMPT"
    assert doc["token_usage"]["input_tokens"] == 10
    assert "timestamp" in doc
    # path layout is .memory/traces/<tenant>/<repo>/<run>-<seq>.json
    assert path.parent.name == "api" and path.parent.parent.name == "acme"


def test_write_is_fail_silent_on_a_bad_path():
    # Make the base path a *file*, so creating subdirectories under it fails.
    f = Path(tempfile.mkdtemp(prefix="dle-audit-")) / "not-a-dir"
    f.write_text("x", encoding="utf-8")
    audit = AuditWriter(base_dir=f)  # mkdir(parents=True) under a file -> error, swallowed
    result = asyncio.run(audit.write(
        tenant_id="acme", repo_id="api", agent_run_id="run-1",
        prompt="P", context_snippets={}, usage=TokenUsage()))
    assert result is None  # did not raise
    assert len(audit.errors) == 1


def test_unsafe_ids_are_sanitised_into_path_segments():
    base = _tmp_dir()
    audit = AuditWriter(base_dir=base)
    path = asyncio.run(audit.write(
        tenant_id="ac/me", repo_id="../api", agent_run_id="run 1",
        prompt="P", context_snippets={}, usage=TokenUsage()))
    assert path is not None and path.exists()
    # no path traversal: everything stays under base
    assert base.resolve() in path.resolve().parents
