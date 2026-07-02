"""dle-serve  -  the background distillation daemon.

A resident process that keeps the graph and the injection cache fresh without
ever touching the agents' hot path. Each tick it polls the shared SQLite store
and distils any episodic traces past the eviction threshold (last 20 / 48h),
deletes the raw rows, and refreshes the rendered-context cache the injection
hooks read.

    python -m dual_log_engine.daemon                 # poll the default .memory store
    dle-serve --root .memory --interval 3            # explicit
    DLE_LLM=anthropic DLE_HEADROOM=1 dle-serve        # real Opus distillation, compressed

Stop with Ctrl-C. Fail-soft: a per-tick error is logged to stderr and the loop
keeps running.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .engine import MemoryEngine


async def _loop(engine: MemoryEngine, interval: float) -> None:
    while True:
        try:
            result = await engine.distill_due()
            if result["distilled"]:
                print(f"[dle-serve] distilled {result['distilled']} item(s) "
                      f"across {result['groups']} group(s)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - keep the daemon alive across tick errors
            print(f"[dle-serve] tick error: {type(exc).__name__}: {exc}", file=sys.stderr)
        await asyncio.sleep(interval)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dle-serve", description="dual-log memory background distiller")
    parser.add_argument("--root", default=os.environ.get("DLE_MEMORY_DIR", ".memory"),
                        help="memory store directory (default: .memory or $DLE_MEMORY_DIR)")
    parser.add_argument("--interval", type=float, default=float(os.environ.get("DLE_INTERVAL", "3")),
                        help="seconds between distillation ticks (default: 3)")
    args = parser.parse_args(argv)

    engine = MemoryEngine(root=args.root)
    print(f"[dle-serve] watching {args.root}, every {args.interval}s "
          f"(llm={type(engine.llm).__name__})", file=sys.stderr)
    try:
        asyncio.run(_loop(engine, args.interval))
    except KeyboardInterrupt:
        print("[dle-serve] stopped", file=sys.stderr)


def run() -> None:
    """Console-script entry point."""
    main()


if __name__ == "__main__":
    main()
