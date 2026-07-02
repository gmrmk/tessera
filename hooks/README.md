# Context-injection hooks

A suite of Claude Code hooks that wire the dual-log memory engine into a live
session. They turn the engine into an automatic, two-way memory layer: the
session *reads* distilled insight on the way in and *writes* its activity on the
way out  -  no manual tool calls.

| Hook | Event | What it does |
| --- | --- | --- |
| `session_start_inject.py` | SessionStart | Injects this repo's durable **HIGH-tier** insights (architectural principles, recurring-failure guidelines) as additional context. |
| `user_prompt_submit_inject.py` | UserPromptSubmit | Injects **HYBRID-tier** memory relevant to the prompt. |
| `post_tool_use_capture.py` | PostToolUse | Captures each tool call (name + key inputs + a slice of the result) as an episodic trace; the engine distils on eviction. |
| `stop_distill.py` | Stop | Flushes/distils the remaining buffer at session end so nothing is lost. |

All hooks are **fail-silent**: if the engine can't be imported or anything
throws, the hook injects/ingests nothing and exits 0. A memory hook must never
break a session.

## Install

```bash
cd reference-impl
pip install -e .          # so the hooks can import dual_log_engine
```

(If it isn't installed, the hooks fall back to importing from the sibling `src/`.)

Then copy the relevant entries from [`settings.snippet.json`](settings.snippet.json)
into your `.claude/settings.json` `hooks` section, replacing `<ABS>` with this
repo's absolute path.

## Configuration (env vars)

| Variable | Default | Meaning |
| --- | --- | --- |
| `DLE_MEMORY_DIR` | `<cwd>/.memory` | Where the shared store lives (graph + buffers + audit). |
| `DLE_TENANT_ID` | `local` | Tenant isolation key. |
| `DLE_REPO_ID` | working-dir name | Repo isolation key. |
| `DLE_LLM` | `mock` | `anthropic` to distil with Claude Opus 4.8 (needs `[llm]` + a key). |
| `DLE_HEADROOM` | unset | `1` to compress the batch via Headroom before the LLM (needs `[headroom]`). |

Out of the box the hooks use the deterministic mock distiller  -  fast, offline,
no key. Set `DLE_LLM=anthropic DLE_HEADROOM=1` to run real Opus distillation with
Headroom compression ("maxx the tokens, not the credit card").

## Relationship to the MCP server

The hooks and the MCP server share the **same on-disk store** (`DLE_MEMORY_DIR`).
Use the hooks for automatic, hands-off capture/injection inside Claude Code; use
the MCP server (`dle-mcp`) when you want an agent to query or write memory
explicitly as tool calls. They compose.

## Relationship to the repo's other hooks

These are **context-injection** hooks for the reference engine and live here,
under `reference-impl/hooks/`. They are separate from the repo's top-level
`hooks/` (the `.mjs` governance gates), which are unchanged.
