"""Ingest - the agnostic backbone. A diff + who made it -> a recorded, scanned change.

Agent-agnostic by construction: it parses the *output* (a unified diff) and an
attribution, so it works identically whether Claude, GPT, Cursor, or a human
produced the change. Attribution can be passed in by the caller (an org's CI
knows who ran), or inferred from commit-message trailers like
`Co-Authored-By: Claude <...>`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .chain import GovernanceChain
from .safety.engine import Finding, scan_lines
from .store import GovernanceStore, _tenant_key


@dataclass
class Attribution:
    # Bare-construction default is "unknown"; the wired callers (server.py, cli.py,
    # infer_attribution) substitute "human" for an absent agent.
    author: str = "unknown"
    agent: str = "unknown"  # "claude" | "gpt" | "copilot" | "cursor" | "human" | ...


# Non-exhaustive allowlist; any unrecognized agent is recorded as "human"
# (best-effort attribution).
_AGENT_TRAILERS = {
    "claude": re.compile(r"(?i)co-authored-by:\s*claude"),
    "gpt": re.compile(r"(?i)co-authored-by:\s*(chatgpt|gpt|openai)"),
    "copilot": re.compile(r"(?i)co-authored-by:\s*(github\s+)?copilot"),
    "cursor": re.compile(r"(?i)co-authored-by:\s*cursor"),
}


def infer_attribution(commit_message: str, author: str = "unknown") -> Attribution:
    """Infer the agent from commit trailers; default to 'human' if none present.

    Library helper only: the wired server/CLI entrypoints require the caller to
    pass an explicit agent and do NOT auto-infer from a commit message.
    """
    for agent, pat in _AGENT_TRAILERS.items():
        if pat.search(commit_message or ""):
            return Attribution(author=author, agent=agent)
    return Attribution(author=author, agent="human")


def parse_diff(diff: str) -> list[tuple[str, list[tuple[int, str]]]]:
    """Parse a unified diff -> [(file_path, [(new_line_number, added_text), ...]), ...].

    Only *added* lines are scanned (that's what the change introduces). New-file
    line numbers are tracked from each hunk header so findings point at real lines.
    """
    files: list[tuple[str, list[tuple[int, str]]]] = []
    cur_file: str | None = None
    cur_added: list[tuple[int, str]] = []
    new_lineno = 0

    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            if cur_file is not None:
                files.append((cur_file, cur_added))
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            cur_file = None if path == "/dev/null" else path
            cur_added = []
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)  # new-side start line of the hunk
            new_lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            cur_added.append((new_lineno, raw[1:]))
            new_lineno += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            pass  # removed line - does not advance the new-side counter
        elif raw.startswith(" "):
            new_lineno += 1  # context line advances the new-side counter
        # diff --git / index / --- headers: ignored

    if cur_file is not None:
        files.append((cur_file, cur_added))
    return files


def ingest_change(
    store: GovernanceStore,
    chain: GovernanceChain,
    org: str,
    repo: str,
    diff: str,
    attribution: Attribution,
    sha: str | None = None,
) -> dict:
    """Record a change, scan its added lines, store findings, append to the chain."""
    _tenant_key(org)  # validate the tenant up front: a blank/invalid org fails cleanly with
    #                   ValueError before any diff parsing (the CLI path had no edge check).
    files = parse_diff(diff)
    findings: list[Finding] = []
    for path, added in files:
        findings.extend(scan_lines(path, added))

    summary = f"{len(files)} file(s) changed; {len(findings)} finding(s)"
    change_id = store.add_change(org, repo, sha, attribution.author, attribution.agent, summary)
    for f in findings:
        store.add_finding(change_id, org, repo, f.as_row())
    store.set_change_findings(org, change_id, len(findings))

    # Tamper-evident trail. The chain payload records check/severity/file/line and
    # never the snippet itself; DB-snippet redaction is separately best-effort
    # (see engine.redact). So the ledger payload carries no snippet to leak.
    entry = chain.append(org, {
        "change_id": change_id, "repo": repo, "sha": sha,
        "author": attribution.author, "agent": attribution.agent,
        "files": [p for p, _ in files],
        "findings": [
            {"check": f.check_id, "severity": f.severity, "file": f.file, "line": f.line}
            for f in findings
        ],
    })

    return {
        "change_id": change_id,
        "findings": findings,
        "n_findings": len(findings),
        "chain_seq": entry["seq"],
        "files": [p for p, _ in files],
    }
