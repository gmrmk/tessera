# Demo repository policy

- Never read, write, print, or commit secrets or `.env` files.
- Do not run destructive commands such as `rm -rf`, `git reset --hard`, or unleased force pushes.
- Production deployments require explicit human approval and a named rollback path.
- Changes to `CLAUDE.md`, `.claude/settings.json`, hooks, or `.mcp.json` must be reviewed.
- Always run tests before claiming the work is fully resolved.
- Prefer small, understandable changes over impressive rewrites.
