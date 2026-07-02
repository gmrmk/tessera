# Provenance

This repository is a clean-room export of the `reference-impl` package from the
`dual-log-memory` working repository.

- **Source repo:** `dual-log-memory` (working/private repo)
- **Source path:** `reference-impl/` (contents copied to this repo's root)
- **Source branch:** `feat/agent-governance`
- **Source commit:** `429339f`
- **Export date:** 2026-07-01

## What was excluded from the export

The following were deliberately not copied from the source tree:

- `.git/` (fresh history is initialized in this repo instead)
- `.claude/` (agent tooling configuration)
- `CLAUDE.md` (agent operating instructions)
- `references/` (internal persona/reference material)
- `dashboard-preview.html`
- `__pycache__/`, `.pytest_cache/`, `*.egg-info/` (generated artifacts)
- `.memory/`, `.governance/` (runtime output: audit ledger / governance DB default paths)

## Sanitization applied

A full sweep of the copied tree was run for the following classes of content.
**No matches were found**, so no files required editing:

- Maintainer-personal identifiers: email addresses, OS usernames, and absolute
  machine paths from the development environment
- Development-session tooling residue (local agent/memory tooling names and
  session artifacts)
- Standard secret patterns: API keys, tokens, connection strings, PEM private
  key blocks, vendor-specific credential formats (AWS, GitHub, Google OAuth,
  Slack, SendGrid, JWTs)
- Private/internal IP address literals

Every apparent match surfaced by the sweep was reviewed and confirmed to be one
of:

- A test/demo fixture used to exercise the governance layer's own secret- and
  PII-detection engine (e.g. `sk-...`-shaped fake keys, `jane.doe@acmecorp.com`,
  `test@example.com`, Luhn-valid test credit card numbers)  -  these are
  load-bearing for the test suite and were left in place.
- RFC1918/loopback example addresses (`192.168.x`, `10.x`, `172.16-31.x`) used
  in documentation and tests to illustrate the cleartext-transmission detector's
  own regex behavior  -  not references to real internal infrastructure.
- Regex pattern *definitions* for secret formats (e.g. `-----BEGIN ... PRIVATE
  KEY-----`, `gh[pousr]_...`, `github_pat_...`) inside the safety-checking
  source code and its tests  -  deliberately fragmented in source to avoid the
  scanner self-flagging, not actual leaked credentials.

## Known pending work

- **Package rename:** the public console script `tessera` now exists (with the
  legacy `dle-*` scripts kept as aliases). The Python package is still named
  `dual_log_engine` (distribution name `dual-log-engine`); renaming the package
  and its imports to `tessera` is the remaining pending roadmap item, intentionally
  left untouched in this export to keep the tree close to source aside from
  sanitization and the console-script addition.

## Certification (2026-07-01)

Three independent sanitization signals, all clean:

1. Forker sweep at export time (personal identifiers, machine paths, tooling
   residue, 20+ secret patterns): zero edits required.
2. Controller residue greps (two passes, including post-edit re-checks of this
   file and README.md): clean after one fix to this file, which originally
   quoted the identifier strings it certified absent.
3. Deterministic 17-pattern scan (AWS/GitHub/GitLab/Google/Slack/SendGrid/JWT/
   PEM/DB-URL/basic-auth credentials + personal identifiers + machine paths +
   tooling residue) over every text file: zero real matches. Four classified
   fixtures remain by design, all obviously fake and load-bearing for the test
   suite (the documented sk-A1B2... redaction fixture, bare PEM header strings
   with no key material quoted as check descriptions in the feature ledger, and
   the hunter2-style basic-auth fixture in the cleartext tests).

Runtime artifacts created by pre-ship test runs (.memory/, .pytest_cache/,
egg-info) were removed before the initial commit. Result: PASS.

Build certification: fresh virtual environment, pip install -e .[mcp], both
console scripts (tessera, dle-govern) exit 0, full suite 247 passed / 1 xfailed
/ 0 skipped, end-to-end ingest -> verify-chain (ok, signed) -> dashboard render
verified from this tree.
