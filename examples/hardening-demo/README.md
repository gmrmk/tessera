# Tessera Harden synthetic demo

This directory contains only synthetic policy text. It is designed to produce a
complete unsafe-to-verified walkthrough without accessing secrets, production
systems, or private company material.

```bash
# From the Tessera repository root:
pip install -e '.[dev]'

tessera harden audit examples/hardening-demo
tessera harden plan examples/hardening-demo
tessera harden apply examples/hardening-demo

tessera harden apply examples/hardening-demo --write
tessera harden verify examples/hardening-demo --break-each-rule
tessera harden report examples/hardening-demo \
  --format html \
  --out examples/hardening-demo/.tessera/report.html
```

The first `apply` is a dry run. The second installs only inside this demo directory.
The 49-case verification suite deliberately submits destructive commands, secret
paths, governance changes, production operations, unsupported closure claims, stale
test evidence, and artifact drift to the generated hook. None of the commands are
executed; the runtime receives the same JSON-shaped inputs used by Claude Code hooks.

Inspect these generated handoff artifacts:

- `.tessera/governance-inventory.json`
- `.tessera/rule-to-hook-map.md`
- `.tessera/verification.json`
- `.tessera/report.html`

Preview and restore the demo's prior state:

```bash
tessera harden rollback examples/hardening-demo
tessera harden rollback examples/hardening-demo --write
```
