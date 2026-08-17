"""Repository discovery and policy/configuration audit."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .controls import BASELINE_CONTROLS, classify_rule, is_normative
from .model import AuditResult, Finding, Severity

_POLICY_GLOBS = (
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    ".claude/rules/*.md",
    ".claude/rules/**/*.md",
    "policy/*.md",
    "policy/**/*.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"project root does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"project root is not a directory: {path}")
    return path


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def discover_policy_files(root: Path) -> list[Path]:
    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in _POLICY_GLOBS:
        for path in root.glob(pattern):
            if path.is_file():
                resolved = path.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(path)
    return sorted(files, key=lambda p: _relative(root, p))


def _candidate_policy_text(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith("<!--"):
        return None
    text = re.sub(r"^#{1,6}\s+", "", text)
    text = re.sub(r"^[-*+]\s+\[[ xX]\]\s+", "", text)
    text = re.sub(r"^[-*+]\s+", "", text)
    text = re.sub(r"^\d+[.)]\s+", "", text)
    if len(text) < 8 or not is_normative(text):
        return None
    return text


def extract_rules(root: Path, files: Iterable[Path]):
    rules = []
    for path in files:
        rel = _relative(root, path)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            text = _candidate_policy_text(line)
            if text:
                rules.append(classify_rule(rel, line_number, text))
    return rules


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw)
    except FileNotFoundError:
        return None, None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"{exc.__class__.__name__}: {exc}"
    if not isinstance(value, dict):
        return None, "top-level JSON value must be an object"
    return value, None


def _hook_commands(settings: dict[str, Any]) -> list[str]:
    """Return searchable command lines, including structured handler args."""
    commands: list[str] = []
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return commands
    for groups in hooks.values():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for handler in group.get("hooks", []):
                if isinstance(handler, dict) and isinstance(handler.get("command"), str):
                    pieces = [handler["command"]]
                    args = handler.get("args")
                    if isinstance(args, list):
                        pieces.extend(str(arg) for arg in args if isinstance(arg, (str, int, float)))
                    commands.append(" ".join(pieces))
    return commands


def _hook_events(settings: dict[str, Any]) -> set[str]:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return set()
    return {event for event, groups in hooks.items() if isinstance(groups, list) and groups}


def _literal_mcp_secret_keys(mcp: dict[str, Any]) -> list[str]:
    servers = mcp.get("mcpServers", mcp.get("servers", {}))
    if not isinstance(servers, dict):
        return []
    hits: list[str] = []
    sensitive = re.compile(r"(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)", re.I)
    reference = re.compile(r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$")
    for server_name, config in servers.items():
        if not isinstance(config, dict):
            continue
        env = config.get("env")
        if not isinstance(env, dict):
            continue
        for key, value in env.items():
            if sensitive.search(str(key)) and isinstance(value, str) and value and not reference.match(value.strip()):
                hits.append(f"{server_name}:{key}")
    return sorted(hits)


def _referenced_project_path(command: str, root: Path) -> Path | None:
    marker = "${CLAUDE_PROJECT_DIR}/"
    marker2 = "$CLAUDE_PROJECT_DIR/"
    for prefix in (marker, marker2):
        if prefix in command:
            suffix = command.split(prefix, 1)[1].split()[0].strip("\"'")
            return root / suffix
    return None


def audit_project(root: str | os.PathLike[str]) -> AuditResult:
    project = resolve_root(root)
    policy_files = discover_policy_files(project)
    inputs = [_relative(project, path) for path in policy_files]
    findings: list[Finding] = []

    settings_path = project / ".claude" / "settings.json"
    local_settings_path = project / ".claude" / "settings.local.json"
    mcp_path = project / ".mcp.json"

    settings, settings_error = _load_json(settings_path)
    local_settings, local_error = _load_json(local_settings_path)
    mcp, mcp_error = _load_json(mcp_path)

    for path in (settings_path, local_settings_path, mcp_path):
        if path.exists():
            inputs.append(_relative(project, path))

    if settings_error:
        findings.append(Finding(
            "CFG-JSON-001", Severity.CRITICAL, "Project settings are invalid JSON",
            settings_error, ".claude/settings.json",
            "Repair the JSON before installing or relying on project hooks.",
        ))
    elif settings is None:
        findings.append(Finding(
            "CFG-MISSING-001", Severity.HIGH, "No shareable project hook settings",
            "The repository has no .claude/settings.json, so prose policy is not backed by project-scoped hooks.",
            ".claude/settings.json",
            "Run `tessera harden apply --write` after reviewing the dry-run plan.",
        ))
    else:
        if settings.get("disableAllHooks") is True:
            findings.append(Finding(
                "CFG-DISABLED-001", Severity.CRITICAL, "Project hooks are disabled",
                "disableAllHooks is true in .claude/settings.json.",
                ".claude/settings.json",
                "Remove the flag or set it to false after confirming why it was introduced.",
            ))
        hooks = settings.get("hooks")
        if not isinstance(hooks, dict) or not hooks.get("PreToolUse"):
            findings.append(Finding(
                "CFG-PRETOOL-001", Severity.HIGH, "No PreToolUse enforcement hook",
                "The project settings do not contain a PreToolUse hook capable of blocking a tool before execution.",
                ".claude/settings.json",
                "Install a deterministic PreToolUse guard and verify it with adversarial fixtures.",
            ))
        commands = _hook_commands(settings)
        if any("tessera_guard" in command for command in commands):
            expected_events = {"PreToolUse", "PostToolUse", "Stop", "SessionStart", "ConfigChange"}
            missing_events = sorted(expected_events - _hook_events(settings))
            if missing_events:
                findings.append(Finding(
                    "CFG-TESSERA-PARTIAL-001", Severity.HIGH, "Tessera hook registration is incomplete",
                    f"Missing event registrations: {', '.join(missing_events)}.",
                    ".claude/settings.json",
                    "Re-run `tessera harden apply --write`, then verify the installed package.",
                ))
        for command in commands:
            referenced = _referenced_project_path(command, project)
            if referenced is not None and not referenced.exists():
                findings.append(Finding(
                    "CFG-BROKEN-PATH-001", Severity.HIGH, "Hook references a missing project file",
                    f"Hook command references {referenced.relative_to(project).as_posix()}, but that path does not exist.",
                    ".claude/settings.json",
                    "Restore the referenced hook or remove the stale settings entry.",
                ))

    if local_error:
        findings.append(Finding(
            "CFG-LOCAL-JSON-001", Severity.HIGH, "Local settings are invalid JSON",
            local_error, ".claude/settings.local.json",
            "Repair or remove the invalid local settings file.",
        ))
    elif local_settings and isinstance(local_settings.get("hooks"), dict):
        findings.append(Finding(
            "CFG-LOCAL-ONLY-001", Severity.MEDIUM, "Hook configuration exists in a non-shareable local file",
            "settings.local.json is normally not committed, so teammates and cloud sessions may not receive these controls.",
            ".claude/settings.local.json",
            "Move team-required hooks into .claude/settings.json or managed policy settings.",
        ))

    if mcp_error:
        findings.append(Finding(
            "MCP-JSON-001", Severity.HIGH, "MCP configuration is invalid JSON",
            mcp_error, ".mcp.json", "Repair the MCP configuration and re-run the audit.",
        ))
    elif mcp is not None:
        servers = mcp.get("mcpServers", mcp.get("servers", {}))
        names = sorted(servers) if isinstance(servers, dict) else []
        findings.append(Finding(
            "MCP-AUTHORITY-001", Severity.MEDIUM, "MCP authority requires human review",
            "Configured MCP servers can add tools and authority beyond local filesystem hooks"
            + (f": {', '.join(names)}." if names else "."),
            ".mcp.json",
            "Review each server's transport, credentials, write scope, and approval rules; hooks can match MCP tool names but cannot infer business authorization.",
        ))
        literal_secret_keys = _literal_mcp_secret_keys(mcp)
        if literal_secret_keys:
            findings.append(Finding(
                "MCP-SECRET-001", Severity.CRITICAL, "MCP configuration appears to contain literal credentials",
                "Credential-like environment values are embedded for: " + ", ".join(literal_secret_keys) + ". Values were not read into the report.",
                ".mcp.json",
                "Move credentials to environment-variable references or an approved secret manager, rotate exposed values, and verify repository history.",
            ))

    rules = extract_rules(project, policy_files)
    if not policy_files:
        findings.append(Finding(
            "POLICY-MISSING-001", Severity.MEDIUM, "No policy source discovered",
            "No CLAUDE.md, .claude/rules/*.md, or policy/*.md file was found.",
            None,
            "Create a concise project policy before mapping rules to controls.",
        ))
    elif not rules:
        findings.append(Finding(
            "POLICY-NORMATIVE-001", Severity.LOW, "No normative policy statements extracted",
            "Policy files exist, but Tessera found no lines containing terms such as must, never, always, required, or do not.",
            ", ".join(_relative(project, p) for p in policy_files),
            "Express important constraints as explicit, testable statements.",
        ))

    harden_hook = project / ".claude" / "hooks" / "tessera_guard.mjs"
    inventory = project / ".tessera" / "governance-inventory.json"
    verification = project / ".tessera" / "verification.json"
    if harden_hook.exists():
        inputs.append(_relative(project, harden_hook))
    if inventory.exists():
        inputs.append(_relative(project, inventory))
    if verification.exists():
        inputs.append(_relative(project, verification))

    return AuditResult(
        root=str(project),
        generated_at=utc_now(),
        inputs=sorted(set(inputs)),
        rules=rules,
        findings=findings,
        controls=list(BASELINE_CONTROLS),
        metadata={
            "policy_file_count": len(policy_files),
            "rule_count": len(rules),
            "settings_present": settings_path.exists(),
            "local_settings_present": local_settings_path.exists(),
            "mcp_present": mcp_path.exists(),
            "harden_hook_present": harden_hook.exists(),
            "verification_present": verification.exists(),
        },
    )
