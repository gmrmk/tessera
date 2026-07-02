#!/usr/bin/env python
"""PostToolUse hook  -  capture tool activity into episodic memory (hot path).

The fastest thing in the suite: one indexed SQLite insert, no LLM, no networkx.
Distillation is the daemon's job, off this path. Fail-silent.

Note: Claude Code payload field names can vary by version; this reads them
defensively (``.get``) and captures whatever is present.
"""
from __future__ import annotations

import json

from _common import ensure_import, make_engine, read_payload, resolve_ids


def _trace_text(payload: dict) -> str:
    tool = payload.get("tool_name", "tool")
    tool_input = payload.get("tool_input", {}) or {}
    response = payload.get("tool_response", payload.get("tool_output", ""))

    parts = [f"tool={tool}"]
    if isinstance(tool_input, dict):
        for field in ("command", "file_path", "path", "query", "url"):
            if tool_input.get(field):
                parts.append(f"{field}={tool_input[field]}")
    resp_text = response if isinstance(response, str) else json.dumps(response, default=str)
    parts.append(f"result={resp_text[:2000]}")
    return " | ".join(parts)


def main() -> None:
    payload = read_payload()
    if not ensure_import():
        return
    try:
        tenant, repo, run = resolve_ids(payload)
        engine = make_engine(payload)
        engine.capture(tenant, repo, run, _trace_text(payload))  # sync, O(1) insert
    except Exception:
        return  # fail-silent


if __name__ == "__main__":
    main()
