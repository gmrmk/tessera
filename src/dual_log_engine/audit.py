"""AuditWriter  -  a non-blocking, fail-silent ledger of every memory transaction.

Each distillation writes one JSON document under ``.memory/traces/`` capturing:
the timestamp, the envelope's tracking ids, the exact prompt string that was
executed, the graph-context snippets that came back, and the true token
consumption.

Two hard requirements from the spec, both honoured here:
  * **Non-blocking**  -  the file write runs in a worker thread via
    ``asyncio.to_thread`` so it never stalls the event loop.
  * **Fail-silent**  -  any exception (a file lock, a bad path, a full disk) is
    swallowed into ``self.errors`` and never propagated, so a broken audit path
    can never take down the primary application thread.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TRACE_DIR = ".memory/traces"
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(segment: str) -> str:
    """Make an id safe to use as a single path segment."""
    cleaned = _UNSAFE.sub("_", segment).strip("._")
    return cleaned or "unknown"


class AuditWriter:
    def __init__(self, base_dir: str | Path = DEFAULT_TRACE_DIR) -> None:
        self.base = Path(base_dir)
        self._seq = 0
        self.errors: list[str] = []  # swallowed write failures, inspectable; never raised

    def _doc(self, tenant_id, repo_id, agent_run_id, prompt, context_snippets, usage) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "repo_id": repo_id,
            "agent_run_id": agent_run_id,
            "prompt": prompt,
            "context_snippets": context_snippets,
            "token_usage": asdict(usage) if is_dataclass(usage) else usage,
        }

    def _write_sync(self, tenant_id, repo_id, agent_run_id, seq, doc) -> Path:
        directory = self.base / _safe(tenant_id) / _safe(repo_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{_safe(agent_run_id)}-{seq}.json"
        path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        return path

    async def write(
        self,
        *,
        tenant_id: str,
        repo_id: str,
        agent_run_id: str,
        prompt: str,
        context_snippets: Any,
        usage: Any,
    ) -> Path | None:
        """Write one audit document off-thread. Returns the path, or None on a
        (swallowed) failure  -  never raises."""
        self._seq += 1
        seq = self._seq
        try:
            doc = self._doc(tenant_id, repo_id, agent_run_id, prompt, context_snippets, usage)
            return await asyncio.to_thread(self._write_sync, tenant_id, repo_id, agent_run_id, seq, doc)
        except Exception as exc:  # noqa: BLE001 - deliberate fail-silent boundary
            self.errors.append(f"{type(exc).__name__}: {exc}")
            return None
