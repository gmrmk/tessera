"""MCP server  -  exposes the dual-log memory engine as MCP tools.

Any MCP client (Claude Code, another agent) can capture traces, query distilled
memory by abstraction tier, force distillation, flush, or read stats. State is
persisted to the SQLite store under ``DLE_MEMORY_DIR`` (default ``.memory/``), so
it survives restarts and is shared with the hooks and the ``dle-serve`` daemon.

Run it:
    python -m dual_log_engine.mcp_server      # stdio transport (local)
    dle-mcp                                   # same, via the console script

Wire it into Claude Code (``.claude/settings.json`` / MCP config):
    {
      "mcpServers": {
        "dual-log-memory": { "command": "python", "args": ["-m", "dual_log_engine.mcp_server"] }
      }
    }

Requires ``pip install dual-log-engine[mcp]`` (the official ``mcp`` SDK).
"""
from __future__ import annotations

import os
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .engine import MemoryEngine

# One engine per server process, persisted under DLE_MEMORY_DIR.
_engine = MemoryEngine(root=os.environ.get("DLE_MEMORY_DIR", ".memory"))

mcp = FastMCP("dual-log-memory")

_MODES = ("LOW", "HIGH", "HYBRID")


@mcp.tool()
def memory_ingest(tenant_id: str, repo_id: str, agent_run_id: str, text: str) -> dict:
    """Capture one raw execution trace into episodic memory (fast, indexed insert).

    Distillation into the dual-level knowledge graph happens in the background  - 
    run the `dle-serve` daemon, or call `memory_distill` / `memory_flush`.

    Args:
        tenant_id: Enterprise/account container id (isolation boundary).
        repo_id: Target repository id (isolation boundary).
        agent_run_id: The execution/trace-thread id this trace belongs to.
        text: The raw operational log / trace text.

    Returns: {buffered}  -  how many traces are queued for this group.
    """
    return _engine.capture(tenant_id, repo_id, agent_run_id, text)


@mcp.tool()
async def memory_query(tenant_id: str, repo_id: str, query: str, mode: str = "HYBRID") -> dict:
    """Retrieve distilled memory for a tenant/repo as injectable context.

    Read-only. Returns a tier-filtered slice compiled into a prompt block.

    Args:
        tenant_id: Isolation boundary  -  only this tenant's memory is returned.
        repo_id: Isolation boundary  -  only this repo's memory is returned.
        query: The natural-language question driving retrieval.
        mode: "LOW" (pinpoint debugging), "HIGH" (systemic overview), or
            "HYBRID" (both tiers, the default).

    Returns: {mode, entities, relations, prompt, token_estimate}.
    """
    mode_u = mode.upper()
    if mode_u not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    ctx = await _engine.query(tenant_id, repo_id, query, mode_u)  # type: ignore[arg-type]
    return {
        "mode": ctx.mode,
        "entities": ctx.entities,
        "relations": ctx.relations,
        "prompt": ctx.to_prompt(),
        "token_estimate": ctx.token_estimate,
    }


@mcp.tool()
async def memory_distill(tenant_id: Optional[str] = None, repo_id: Optional[str] = None) -> dict:
    """Distil overdue buffered traces into the graph now (what the daemon does each tick).

    With no ids, sweeps every group; with both ids, just that group.
    Returns: {groups, distilled}.
    """
    return await _engine.distill_due(tenant_id, repo_id)


@mcp.tool()
async def memory_flush(tenant_id: str, repo_id: str) -> dict:
    """Distil a group's entire current buffer now (e.g. at session end).

    Returns: {flushed, distilled} counts.
    """
    return await _engine.flush(tenant_id, repo_id)


@mcp.tool()
def memory_stats(tenant_id: Optional[str] = None, repo_id: Optional[str] = None) -> dict:
    """Report graph size and (optionally) a tenant/repo-scoped breakdown. Read-only."""
    return _engine.stats(tenant_id, repo_id)


def run() -> None:
    """Console-script / module entry point (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    run()
