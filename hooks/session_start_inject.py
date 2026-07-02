#!/usr/bin/env python
"""SessionStart hook  -  inject the repo's durable HIGH-tier insights.

Reads the daemon-maintained context cache (a single SELECT, no graph traversal);
falls back to a live HIGH-tier query if the cache is cold. Injects only when
there is actual content. Fail-silent; never blocks.
"""
from __future__ import annotations

from _common import emit_additional_context, ensure_import, make_engine, read_payload, resolve_ids


def main() -> None:
    payload = read_payload()
    if not ensure_import():
        return
    try:
        tenant, repo, _run = resolve_ids(payload)
        engine = make_engine(payload)
        text = engine.cached_context(tenant, repo, "HIGH")
        if not text:
            import asyncio
            ctx = asyncio.run(engine.query(tenant, repo, "durable guidelines and recurring risks", "HIGH"))
            text = ctx.to_prompt()
        if "\n- " in text:  # at least one entity/relation bullet
            emit_additional_context(
                "SessionStart", "## Dual-log memory  -  durable insights for this repo\n" + text)
    except Exception:
        return  # fail-silent: a memory hook must never break a session start


if __name__ == "__main__":
    main()
