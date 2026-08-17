# Tessera Harden

Tessera Harden converts a repository's Claude Code policy into a project-scoped,
reversible enforcement package and then attempts to break that package on purpose.
It is built for engineering teams and consultants moving from prose-only
`CLAUDE.md` instructions to controls with installation hashes, adversarial fixtures,
and a handoff report that states its limits.

The runtime is deterministic. No LLM, network call, telemetry service, or third-party
JavaScript package participates in a hook decision.

## Complete workflow

```bash
# 1. Inspect policy, project settings, hook coverage, and MCP authority.
tessera harden audit .

# 2. Map normative statements to honest enforcement statuses.
tessera harden plan .

# 3. Preview the exact project-scoped file changes. Dry-run is the default.
tessera harden apply .

# 4. Install after reviewing the plan.
tessera harden apply . --write

# 5. Exercise the complete adversarial suite and bind the result to artifact hashes.
tessera harden verify . --break-each-rule

# 6. Produce a client or team handoff report.
tessera harden report . --format markdown --out .tessera/report.md
tessera harden report . --format html --out .tessera/report.html

# 7. Preview and perform a transactional rollback.
tessera harden rollback .
tessera harden rollback . --write
```

## What gets installed

| Path | Purpose |
|---|---|
| `.claude/hooks/tessera_guard.mjs` | Node built-ins-only multi-event hook runtime |
| `.claude/tessera-policy.json` | Team-editable path globs, production markers, test commands, and receipt locations |
| `.claude/settings.json` | Idempotent, non-destructive merge of five project hook registrations |
| `.tessera/.gitignore` | Keeps local receipts, state, reports, backups, and manifests out of commits |
| `.tessera/governance-inventory.json` | Policy provenance, controls, statuses, and installation contract |
| `.tessera/rule-to-hook-map.md` | Human-readable policy-to-control handoff map |
| `.tessera/install-manifest.json` | Active install hashes and rollback pointers |
| `.tessera/backups/<manifest-id>/` | Pre-install bytes and immutable historical manifest |
| `.tessera/verification.json` | Adversarial results bound to hook, policy, settings, runtime, and manifest |
| `.tessera/receipts/hooks.jsonl` | Operational metadata-only receipts |
| `.tessera/receipts/verification-hooks.jsonl` | Synthetic verification receipts, kept separate from operations |
| `.tessera/state/<session>.json` | Local bounded test-reminder state |

Raw tool commands and file contents are not written into receipts. Receipts retain
rule IDs, decisions, event and tool names, timestamps, and hashes of inputs or paths.
Matched secret values are withheld from hook output.

## Hook events

Tessera registers one runtime across five Claude Code events:

| Event | Role |
|---|---|
| `PreToolUse` | Deny narrow catastrophic or secret operations; ask for production and governance changes |
| `PostToolUse` | Observe successful file changes and recognized test commands |
| `Stop` | Warn when changes are newer than observed test evidence, with a bounded reminder count |
| `SessionStart` | Compare installed artifact hashes with the active installation manifest |
| `ConfigChange` | Record configuration-change metadata without pretending an external edit was reversed |

The settings merge preserves unrelated permissions and hooks. Reapplying an unchanged
installation is a true no-op and does not overwrite the prior rollback point.

## Enforcement labels

Tessera does not label every policy sentence “enforced.”

- `ENFORCED`: a narrow deterministic condition is denied before tool execution.
- `REQUIRES-HUMAN-APPROVAL`: the hook recognizes a risky class, but authorization or
  context must be decided by an accountable person.
- `WARN-ONLY`: the runtime can surface evidence or inconsistency but cannot prove the
  broader claim.
- `NOT-TECHNICALLY-ENFORCEABLE`: intent, quality, architecture, or business judgment
  cannot be safely reduced to this deterministic hook.

## Baseline controls

1. **Secret and protected-path guard.** Denies high-confidence credential material,
   private-key blocks, credential-bearing URLs, and access to configured secret paths.
2. **Irreversible-operation guard.** Denies a narrow catastrophic set across Git,
   filesystems, SQL, Terraform, Kubernetes, S3, Docker, PowerShell, and Windows shell.
3. **Production approval gate.** Escalates likely production mutations using
   organization-customizable markers.
4. **Governance self-modification gate.** Escalates changes to Claude settings, hooks,
   MCP configuration, policy files, and Tessera's own enforcement artifacts.
5. **Closure-claim warning.** Escalates absolute Git commit claims that do not name an
   independent proving signal.
6. **Post-change test reminder.** Observes successful edits and test commands, then
   warns before stopping when test evidence is older than the edits. The warning is
   bounded rather than trapping the session.
7. **Installed-artifact drift warning.** Warns at session start when installed hook,
   policy, or inventory hashes no longer match the active manifest.
8. **Human-review boundary.** Keeps judgment-heavy statements visible instead of
   converting them into fictional enforcement.

## Adversarial verification

The current baseline contains 49 deterministic cases. It includes benign
counterexamples as well as deliberate violations covering:

- combined, split, long-form, and simply obfuscated destructive command flags;
- direct, traversal, shell, and embedded-interpreter access to protected paths;
- credential reflection resistance and safe removal of an existing secret;
- Claude settings, hook, policy, MCP, and `CLAUDE.md` self-modification;
- production versus development mutations;
- unsupported absolute completion claims versus evidence-backed claims;
- successful edits, stale test evidence, bounded reminders, and newer test receipts;
- quiet and drifted session starts; and
- operational-versus-synthetic receipt separation.

A green receipt is meaningful only for the named cases and the exact artifact hashes
recorded in `.tessera/verification.json`. The report changes its verdict to `STALE`
when those installed bytes or the active manifest no longer match.

## Rollback model

Installation backs up every replaced file before any target is changed and uses
atomic replacement writes. Rollback has a complete preflight phase:

- if any managed file differs from its installed hash, the default rollback refuses
  to alter any managed file;
- a successful rollback restores updated files, removes files Tessera created, and
  removes the active manifest; and
- the historical manifest and backups remain under the manifest-specific backup
  directory for review.

`--force` exists for an operator who has reviewed current drift. It is not the normal
path.

## Audit coverage and evidence gaps

`audit` reviews policy sources, shareable and local Claude settings, hook path
integrity, required Tessera event registrations, and MCP configuration. Credential-like
literal values in MCP environment entries are reported by server and key name without
copying their values into the report.

The report explicitly distinguishes:

- `PASS`: verification passed and matches the active manifest and current artifacts;
- `STALE`: a prior green receipt no longer describes the current installation;
- `FAIL`: one or more named fixtures failed; and
- `NOT-VERIFIED`: no verification receipt exists.

## Customization

Edit `.claude/tessera-policy.json` to extend protected-path globs, exceptions,
production markers, and recognized test commands. Treat policy edits as reviewed
code. After any policy, settings, or hook change, rerun:

```bash
tessera harden audit .
tessera harden verify . --break-each-rule
tessera harden report . --format html --out .tessera/report.html
```

## Provenance

The control architecture adapts destructive-operation, secret-scan, and two-signal
closure concepts from the sibling `gmrmk/trust-but-verify` repository (MIT) and
integrates them with Tessera's provenance and non-overclaiming model. The Node runtime,
transactional installer, verification harness, drift model, and evidence report in
this module are Tessera Harden implementations.

## Boundary statement

Tessera Harden is a configuration, enforcement, and diligence aid. It is not legal
advice, a penetration test, a security certification, a compliance attestation, or a
substitute for accountable human approval and professional security review.
