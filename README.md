# Tessera

**Trust the agent. Verify the mosaic.**

AI agents write production code now. Tessera is the layer that makes that provable
instead of hopeful: a tamper-evident, attributable evidence trail for every change
any agent or any human ships, produced by a scanner that is not allowed to guess.

In the ancient Mediterranean, a *tessera hospitalis* was a trust token snapped in
two. Neither half meant anything alone. Only the fit proved the bond. Tessera holds
your codebase to the same standard: no finding exists on one signal, no check runs
without a cited authority, and the whole record is set like a mosaic. Pry one tile
and the break shows.

## Why it exists

Every organization is running the same experiment right now: hand the codebase to
AI agents and hope the velocity outruns the risk. The velocity is real. So is the
question nobody can answer six months later: *who wrote this line, was it checked,
and can you prove the record was not altered?*

Today most orgs pick between two bad policies. Ban the agents and lose the
productivity, or allow them blind and lose the accountability. Tessera is the third
option: allow everything, evidence everything. Developers keep whatever tools they
like. The organization keeps a record it can stand behind when the incident review,
the auditor, or the board comes asking. Hope is not an answer. A verified mosaic is.

## Why organizations run it

- **Adopt agents without adopting blindness.** The policy question changes from
  "which AI tools do we permit" to "every change is attributed, gated, and sealed,
  whoever or whatever wrote it." That is a policy you can actually enforce.
- **One evidence trail that survives tool churn.** Tessera scans the diff, not the
  agent. Copilot today, Cursor next quarter, the next thing after that: the
  governance layer does not move, and there is no per-vendor integration to rebuild.
- **Evidence in the examiner's grammar.** Every asserted control mapping carries a
  citation; regimes that are not verified yet are listed as pending instead of
  claimed. An audit record that refuses to overclaim is the kind an examiner can
  trust: complete for what was ingested, attributable, contemporaneous,
  integrity-protected, producible on demand.
- **Incident forensics with names.** When something ships broken, the questions
  answer themselves: which hand laid the tile, what did the gate say at the time,
  and the chain proves nobody rewrote the story afterward.
- **Costs one CI step.** A git hook or pipeline step feeding diffs. No proxy, no
  IDE plugin, no change to how developers work, no server fleet: SQLite and a
  webhook. Pilot it on one repo this afternoon.
- **The honesty is the point.** A governance record that exaggerates is a liability
  wearing a badge. Tessera states its limits in the product, in the docs, and on
  the dashboard, which is precisely what makes the claims it does assert worth
  something.

## What it does

Point it at a diff. Any source: Claude, GPT, Copilot, Cursor, a colleague.

- **Attributes** the change: which hand laid the tile, agent or human, recorded first-class.
- **Scans** it with grounded checks: every check cites OWASP, CWE, GDPR, or NIST at
  construction, or it refuses to exist.
- **Gates** every finding on two independent signals: detect AND verify, or silence.
  A pattern match alone is a rumor.
- **Redacts** secrets before anything reaches disk, so the evidence store is safe to
  keep and back up.
- **Seals** change and findings into an HMAC-signed, per-org hash chain with a signed
  anchor. Rewrite a row, verification breaks. Truncate the tail, the frame catches it.
- **Answers** as an org report, a cited compliance view, and a dashboard built to be
  interrogated, not glanced at.
- **Hardens Claude Code projects** by mapping prose policy to project-scoped hooks,
  deliberately attempting to bypass them, and producing reversible installation and
  evidence receipts without an LLM in the enforcement path.

## Claude Code hardening

`Tessera Harden` turns `CLAUDE.md`, `.claude/rules/*.md`, Claude settings, and MCP
configuration into an honest policy inventory and a tested project hook package.
It labels each statement as `ENFORCED`, `REQUIRES-HUMAN-APPROVAL`, `WARN-ONLY`, or
`NOT-TECHNICALLY-ENFORCEABLE` instead of claiming every sentence can become code.

```bash
# Inspect and plan without changing files.
tessera harden audit .
tessera harden plan .
tessera harden apply .

# Install, attempt to break every baseline control, and render a handoff report.
tessera harden apply . --write
tessera harden verify . --break-each-rule
tessera harden report . --format html --out .tessera/report.html

# Preview and perform a reversible uninstall.
tessera harden rollback .
tessera harden rollback . --write
```

Installation and rollback are dry-run by default. Tessera preserves unrelated
settings and hooks, installs a Node built-ins-only runtime across `PreToolUse`,
`PostToolUse`, `Stop`, `SessionStart`, and `ConfigChange`, writes atomically, and
backs up replaced files. Rollback is transactional: a conflict blocks the entire
operation unless an operator explicitly forces it. The 49-case verification receipt
is bound to the installed hook, policy, settings, and manifest; the report marks a
formerly green installation `STALE` when those bytes change. Global user settings are
never modified. See `docs/HARDENING.md` and `examples/hardening-demo/`.

## The vocabulary

The metaphor is the architecture.

| The craft | The code |
|---|---|
| **the tessera** - one tile | one grounded finding |
| **the fit** - both halves must match | the two-signal detect-verify gate |
| **the quarry** - where the tile is cut | the citation registry; no source, no check |
| **the hand** - who laid it | per-change agent/human attribution |
| **the setting** - the bed that shows tampering | the HMAC-signed hash chain |
| **the frame** - the fixed edge | the signed anchor; truncation shows |
| **the mosaic** - the whole picture | the org's evidence trail |

## What Tessera will not tell you

A governance tool that overclaims is itself ungoverned. The limits ship as features:

- Detection is lexical: patterns plus an independent verify, not dataflow analysis.
  A determined multi-line evasion beats it. Documented, pinned by a deliberate
  failing test, and on the roadmap (semantic backends wrapped as grounded sources).
- Redaction is best-effort. Known formats and high-entropy literals are masked; an
  exotic credential shape may not be. The robust control is not hardcoding secrets,
  which Tessera flags.
- Keyless mode says so: without an out-of-DB signing key the chain catches accidents,
  not adversaries, and `verify()` reports `signed: false` rather than borrowing trust
  it has not earned.
- Absence of a finding is not proof of safety. The dashboard states this before it
  shows you a single number.
- A green hardening receipt proves the named fixtures against the recorded hook hash;
  it is not a penetration test, legal opinion, or compliance certification.

## Receipts

- A broad test suite plus deliberately-failing pins on documented limits.
- A 73-row feature ledger (`docs/FEATURE-STATUS.csv`) where every GREEN carries the
  test that proves it.
- A 355-item uncertainty census, every item resolved and published in-repo
  (`docs/UNCERTAINTY-CENSUS.md`, `docs/UNCERTAINTY-CENSUS-RESOLUTION.md`).
- Adversarial multi-pass review: zero critical, zero high; every confirmed finding
  fixed, every intentional limit documented (`docs/SECURITY-HARDENING.md`).
- Tessera Harden adds policy provenance, transactional installation and rollback,
  metadata-only operational receipts, separate synthetic verification receipts,
  installed-artifact drift detection, and a 49-case adversarial fixture report.

## Quickstart

```
pip install -e .
tessera ingest --org acme --repo api --diff-file change.diff --author alice --agent claude
tessera verify-chain --org acme
tessera dashboard --org acme > mosaic.html
```

Set `DLE_CHAIN_KEY` (an out-of-DB secret) in production for HMAC tamper-evidence.
Webhook mode, Docker, and operations notes: `src/dual_log_engine/governance/DEPLOY.md`.
The `tessera` command ships now (`dle-govern` stays as a legacy alias). Only the
package/import rename (`dual_log_engine` to `tessera`) remains on the roadmap; see
`PROVENANCE.md`.

## Provenance

Clean-room export from a private working repository, sanitization swept and
independently certified. Full chain of custody: `PROVENANCE.md`.

## License

Apache-2.0. See `LICENSE`.
