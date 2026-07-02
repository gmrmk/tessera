# Security hardening record

This governance layer was pressure-tested by an adversarial **purple-team swarm** (red
agents execute PoCs -> independent verifiers reproduce -> fixes are TDD'd, each PoC becomes a
regression test). The process ran to convergence over 7 fix-rounds. This document records
what was hardened, and - in the spirit of the product's verified-claims-only discipline -
the **limitations that remain**, so no claim here is overstated.

## What the swarm confirmed

- **0 of 13** originally-confirmed findings reproduce against the current code (as of the
  2026-06-29 swarm run / current HEAD).
- The re-attack/re-probe loop found further residual gaps each round (including a HIGH
  regression a fix itself introduced); all were closed and regression-tested.
- The final convergence check returned **0 blocking issues** (no reproduced finding, no
  over-redaction false-positive that corrupts evidence, no new exploitable class) as of the
  2026-06-29 swarm run / current HEAD.

## Hardened (each carries the purple-team PoC as a regression test)

| Area | Hardening |
|---|---|
| Detection | command-injection + code-injection checks (CWE-78/94); SQLi via `.format`/`%`/`%`-dict/`.format_map`/`executescript`/adjacent-literal/var-either-side concat/any f-string prefix; `executescript` sink |
| Tamper-evidence | audit chain is **HMAC-signed** with an out-of-DB key (`DLE_CHAIN_KEY`) + a signed head/length anchor - a forged or truncated tail now fails `verify()`. Keyless mode reports `signed=false` |
| Redaction | vendor token prefixes (AIza/JWT/glpat/github_pat); substring key-name match; high-entropy fallback (20+ char); URL basic-auth, secret query params, Bearer, explicit `--password=`/`PGPASSWORD=` |
| DoS | ReDoS removed (bounded email regex + per-line scan cap) |
| Multi-tenancy | tenant key normalized (numeric/whitespace/zero-width/BOM rejected uniformly at the store and both HTTP endpoints) |
| Webhook | non-object/non-string/blank input -> 400 (never 500/crash); `do_GET` guarded; banner no longer leaks the Python build |
| Durability | `restore()` fails closed without a verifiable manifest |

## Operator requirement

**Set `DLE_CHAIN_KEY`** (an out-of-DB secret) in production. Without it the chain is SHA-256
linked only - it detects accidental edits but not a key-less forger, and the dashboard/report
say so honestly (`signed=false`). See `DEPLOY.md`.

## Documented limitations (best-effort by design - not regex whack-a-mole)

These are **acknowledged gaps**, consistent with what the product claims:

- **Embedded-credential redaction is best-effort.** It masks common forms (URL basic-auth,
  secret query params, Bearer, explicit DB password flags). It does **not** catch every
  embedded form - e.g. `Proxy-Authorization: Basic <base64>`, arbitrary URI schemes. The
  overloaded `-p` shorthand is deliberately **not** redacted (indistinguishable from a docker
  port / `cp -p` / `grep -p` without semantic analysis; masking it corrupted evidence). The
  real control is **not hardcoding credentials** (which the `secret-hardcoded` check flags),
  and the roadmap fix is a dedicated secret scanner.
- **Detection is heuristic (two-signal regex), not dataflow.** SQL whose keyword lives only
  in a variable (`base_query + " WHERE id=%s" % x`) or is built via `str.join`/`str("...")%x`
  is not detected without taint analysis. The roadmap fix is to back detection with semantic
  analysis (Semgrep / tree-sitter) as additional grounded sources.
- **Chain rollback to a consistent earlier state** (attacker restores both DB and a
  previously-valid anchor) is not detectable locally - it needs an external witness (a
  published head / notary). Documented in `chain.py`.
- **Single-writer SQLite.** One governance instance per store; not a concurrent multi-writer
  backend (roadmap: Postgres).

## Reproducing

Every item above has a test. `cd reference-impl && python -m pytest -q` runs the full suite. The
chain-signing inverse PoC (`test_governance_chain_signing.py`) shows a forged tail failing
`verify()` only when `DLE_CHAIN_KEY` is set.
