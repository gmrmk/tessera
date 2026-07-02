#!/usr/bin/env python
"""UserPromptSubmit hook  -  inject memory relevant to the prompt (HYBRID tier).

Reads the daemon-maintained HYBRID cache (one SELECT); falls back to a live query
keyed on the user's prompt if the cache is cold. Injects only when there is
content. Fail-silent.
"""
from __future__ import annotations

from _common import emit_additional_context, ensure_import, make_engine, read_payload, resolve_ids


def main() -> None:
    payload = read_payload()
    if not ensure_import():
        return
    try:
        tenant, repo, _run = resolve_ids(payload)
        prompt = payload.get("prompt") or "relevant prior context"
        engine = make_engine(payload)
        text = engine.cached_context(tenant, repo, "HYBRID")
        if not text:
            import asyncio
            ctx = asyncio.run(engine.query(tenant, repo, prompt, "HYBRID"))
            text = ctx.to_prompt()
        if "\n- " in text:
            emit_additional_context(
                "UserPromptSubmit",
                "## Dual-log memory  -  possibly-relevant prior context\n" + text, limit=3000)
    except Exception:
        return  # fail-silent


if __name__ == "__main__":
    main()
