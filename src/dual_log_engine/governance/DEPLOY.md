# Deploying the agent-governance webhook

`dle-govern` is a self-hostable webhook that ingests code changes from any
agent's (or human's) CI, scans them with grounded safety checks, and records
everything in a tamper-evident trail. Point your repos' CI at it.

## Run it

```bash
pip install -e .                       # or: pip install .
DLE_GOV_TOKEN=$(openssl rand -hex 16) \
  python -m dual_log_engine.governance.server
# or the console script:
DLE_GOV_TOKEN=... dle-govern-serve
```

Docker:

```bash
docker build -t dle-govern reference-impl
docker run --restart unless-stopped -p 8765:8765 -v dle-data:/data -e DLE_GOV_TOKEN=yourtoken dle-govern
```

`--restart unless-stopped` keeps the webhook running across daemon restarts and
host reboots; persistence is the volume-mounted `/data` plus this restart policy.

## Configuration (environment variables)

| Var | Default | Meaning |
| --- | --- | --- |
| `DLE_GOV_DB` | `.governance/governance.db` | SQLite file - **this is the audit trail; back it up** |
| `DLE_GOV_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | bind address |
| `DLE_GOV_PORT` | `8765` | bind port |
| `DLE_GOV_TOKEN` | unset (auth OFF) | if set, every request must send `X-DLE-Token: <token>` |
| `DLE_CHAIN_KEY` | unset (keyless) | **set this** to a strong out-of-DB secret for HMAC tamper-evidence; keyless mode only catches accidental edits |
| `DLE_CHAIN_KEY_FILE` | unset | alternative to `DLE_CHAIN_KEY`: path to a file holding the signing key |

## Endpoints

| Method - Path | Body / query | Returns |
| --- | --- | --- |
| `POST /ingest` | `{org, repo, diff, author?, agent?, sha?}` | findings JSON |
| `GET /healthz` | - | `{"ok": true}` |
| `GET /dashboard?org=ORG` | - | HTML dashboard |
| `GET /report?org=ORG` | - | text report |
| `GET /compliance?org=ORG` | - | text compliance posture |

## Wiring CI (agent-agnostic)

In a CI step on push/PR, send the diff and who made it:

```bash
DIFF=$(git diff "$BEFORE".."$AFTER")
curl -fsS -X POST "$GOV_URL/ingest" \
  -H "X-DLE-Token: $DLE_GOV_TOKEN" -H "Content-Type: application/json" \
  -d "$(jq -nc --arg o "$ORG" --arg r "$REPO" --arg d "$DIFF" --arg a "$AGENT" \
        '{org:$o, repo:$r, diff:$d, agent:$a}')"
```

`$AGENT` is whatever produced the change (`claude`, `gpt`, `cursor`, `human`, ...)
- the server treats them all identically because it scans the *output*.

## Security notes

- **Terminate TLS in front of this** (reverse proxy / load balancer). The server
  speaks plain HTTP.
- **Set `DLE_GOV_TOKEN`.** Auth is off by default for local use only.
- **Set `DLE_CHAIN_KEY`** (an out-of-DB secret, e.g. from your secret manager) so the
  chain is HMAC-signed: a write-capable attacker without the key cannot forge or truncate
  the trail undetected. Without it the chain is SHA-256 linked (`signed=false`) - it catches
  accidental edits but not a key-less forger. Never commit the key; rotating it invalidates
  prior signatures, so archive the old key with the data it signed.
- The audit trail's integrity is verifiable any time: `tessera verify-chain --org ORG`
  (`dle-govern` is the legacy alias for the same command; or check the dashboard's
  chain banner). A broken chain means the record was altered.
- Snippets in findings are **best-effort** redacted (known secret formats + high-entropy
  literals) before storage; treat the SQLite file like any audit log anyway - it records
  what changed (restricted access, backups).
- Single-writer assumption (no row locking beyond SQLite WAL). Fine for one
  governance instance per store; do not point two writers at the same file.
