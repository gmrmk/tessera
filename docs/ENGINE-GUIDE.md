# dual-log-engine  -  reference implementation

A runnable, **LightRAG-style dual-layer contextual memory engine** that makes the
[`dual-log-memory`](../dual-log-memory/SKILL.md) doctrine executable. The markdown
doctrine and the governance hooks in this repo are unchanged  -  this is a new,
additive Python package.

Three surfaces, one SQLite-backed store: a **library**, an **MCP server**
(`dle-mcp`), and a suite of **context-injection hooks** for Claude Code, with a
**background daemon** (`dle-serve`) doing the heavy work off the hot path. Remote
IO is mocked by default, so it imports and the self-check runs with only
`networkx` installed  -  no network, no API key.

## The doctrine, as code

| Doctrine concept | Engine realization |
|---|---|
| Fix log  -  reactive, "what broke" | Episodic **LOW**-tier traces -> LOW entities/relations |
| Insight log  -  generative, "what worked" | Distilled **HIGH**-tier graph (architectural principles) |
| Synthesis protocol  -  verify a result *transfers* | Distillation keeps only permanent/reusable principles, promoted to HIGH |
| Sunset rules  -  retire the unused | Episodic eviction (last **20** / **48h**); raw traces expire, the distilled graph persists |
| Trust-but-verify | LLM output is untrusted: the store validates, the audit ledger records the exact prompt + output + tokens |

## Architecture (fast path)

```
capture (PostToolUse hook / MCP) -> episodic table        | O(1) indexed insert, no LLM, no networkx
                                        v
                          dle-serve daemon (background)    | polls, distils overdue traces
                                        v
        SqliteStore  -> UPSERT (weight+1 / blend / LOW->HIGH, atomic) --> nodes + edges (indexed)
                                        v
                                  refresh cache
                                        v
inject (SessionStart / UserPromptSubmit hook) --> cache table (1 SELECT)   | no graph traversal
                                        +-> fallback: indexed fetch(tenant, repo, level)
                                  audit ledger -> .memory/traces/  (async, fail-silent)
```

Everything lives in one SQLite file (`<root>/memory.db`, WAL mode), shared by the
hooks, the MCP server, and the daemon  -  SQLite is also the IPC, so there is no
socket protocol.

| Module | Responsibility |
|---|---|
| `store.py` | `SqliteStore`  -  atomic incremental upsert (merge in one SQL statement), indexed `fetch(tenant, repo, level)`, episodic buffer + eviction queries, injection cache. **The default store.** |
| `engine.py` | `MemoryEngine`  -  `capture` (fast), `distill_due` / `flush` (background/at-end), `query`, `cached_context`; env-driven backend (`DLE_LLM`, `DLE_HEADROOM`) |
| `daemon.py` | `dle-serve`  -  resident loop: distil overdue traces, refresh the cache |
| `mcp_server.py` | `dle-mcp`  -  `memory_ingest / query / distill / flush / stats` over the engine |
| `hooks/` | SessionStart + UserPromptSubmit inject, PostToolUse capture, Stop distil ([hooks/README](hooks/README.md)) |
| `envelope.py` | `MemoryEnvelope` + typed `Entity` / `Relation` / `EpisodicTrace` (`TypedDict`) |
| `eviction_worker.py` | distils a batch into any store (duck-typed; no networkx/SQLite import) |
| `rag.py` | `dual_level_rag_query(store, ..., mode=LOW\|HIGH\|HYBRID)` -> `CompiledContext` |
| `audit.py` | `AuditWriter`  -  non-blocking (`asyncio.to_thread`), fail-silent ledger |
| `clients.py` | `LLMClient` protocol - `MockLLMClient` (default) - opt-in `AnthropicLLMClient` (Opus 4.8), `HeadroomLLMClient` |
| `graph_store.py` | `LightRAGGraphStore`  -  the in-memory networkx store (alt backend; powers `demo.py`). Imported on demand, so it is *not* on the hot path. |

## Why it's fast

- **Incremental, atomic writes.** Each upsert is one `INSERT ... ON CONFLICT DO UPDATE`  -  weight `+1`, blend description, elevate LOW->HIGH, all in SQL. No read-modify-write, no full-graph rewrite. (The old networkx+JSON path rewrote the whole store per write -> O(N^2) over a session.)
- **Indexed pre-filter.** `fetch` is `WHERE tenant_id=? AND repo_id=? [AND level=?]` over `(tenant_id, repo_id, level)` indexes  -  O(matching), not O(all tenants). This *is* the spec's database-level pre-filter.
- **networkx-free hot path.** `import dual_log_engine` and `capture` pull in **no networkx** (verified)  -  saving the ~430 ms import on every tool call; capture is a ~1-2 ms indexed insert.
- **Cached injection.** Inject hooks read a pre-rendered cache (1 SELECT), refreshed by the daemon  -  no graph traversal on the prompt path.

## Multi-tenant isolation

Every row carries `tenant_id` / `repo_id`, and every read filters on them in SQL.
Two tenants can share an `entity_name` with zero collision; a query for one tenant
cannot surface another's data.

## Install & run

```bash
cd reference-impl
pip install -e .                    # core: networkx only (mocked IO)
python -c "import dual_log_engine"  # networkx-free import
python -m dual_log_engine.demo      # in-memory self-check (deterministic, no network)
pytest                              # full suite
```

**MCP server** (needs `pip install -e ".[mcp]"`):

```bash
dle-mcp                             # or: python -m dual_log_engine.mcp_server
```

**Background daemon** + **hooks**: see [hooks/README.md](hooks/README.md). The daemon
keeps the graph and the injection cache fresh:

```bash
dle-serve --root .memory --interval 3
```

### Optional real backends (opt-in)

```bash
pip install -e ".[llm]"             # AnthropicLLMClient -> claude-opus-4-8 structured outputs
pip install -e ".[headroom]"        # HeadroomLLMClient -> compress the batch first
```

Switch with env, no code change:

```bash
DLE_LLM=anthropic DLE_HEADROOM=1 dle-serve   # real Opus distillation, compressed
```

`HeadroomLLMClient` compresses the raw batch before the model sees it  -  "maxx the
tokens, not the credit card." The saving is recorded in `TokenUsage.raw_input_tokens`.

## Citation freshness (the trust tree)

Every grounded check cites an authoritative source (`governance/safety/grounding.py`),
and every cited entry carries a `last_verified` date. A version pin grounds a check,
but a pin nobody re-checks rots into the "citation theater" the grounding exists to
prevent. So freshness is enforced, not decorative:

- **Cadence:** re-verify each cited source at least every **90 days** (`STALE_AFTER_DAYS`).
- **Gate:** `tessera verify-grounding` (or `grounding.assert_fresh(today)` from CI / a
  release step) exits non-zero / raises `StaleGroundingError` listing any entry past the
  cadence, so a stale tree fails the build instead of quietly misleading an auditor.
- **To re-verify:** re-fetch the URL, confirm the clause text still matches, bump
  `last_verified` to today; if the source moved, update name/version/url too.

## Scope

v1 retrieval is graph-predicate slicing (no vector store). A real semantic layer is
a documented seam: `sqlite-vec` / LanceDB are the verified embedded stores that do
true metadata **pre-filtering** in both Python and Node; local CPU embeddings via
`fastembed` (`BAAI/bge-small-en-v1.5`, 384-dim)  -  same SQLite file.

License: Apache-2.0 (matches the parent repo).
