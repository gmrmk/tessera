#!/usr/bin/env python
"""Stop hook  -  distil the session's remaining buffer at session end.

A synchronous fallback to the daemon: flush whatever raw traces are still
buffered for this tenant/repo so the session's activity is promoted into the
graph (and the injection cache refreshed) even if no daemon is running.
Fail-silent; never blocks the stop.
"""
from __future__ import annotations

from _common import ensure_import, make_engine, read_payload, resolve_ids


def main() -> None:
    payload = read_payload()
    if not ensure_import():
        return
    try:
        import asyncio
        tenant, repo, _run = resolve_ids(payload)
        engine = make_engine(payload)
        asyncio.run(engine.flush(tenant, repo))
    except Exception:
        return  # fail-silent


if __name__ == "__main__":
    main()
