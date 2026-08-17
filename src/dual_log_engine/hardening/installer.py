"""Generate, install, and roll back project-scoped Claude Code controls."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .model import ApplyResult, FileAction
from .policy import DEFAULT_POLICY
from .scanner import audit_project, resolve_root, utc_now

HOOK_COMMAND = "node"
HOOK_ARG = "${CLAUDE_PROJECT_DIR}/.claude/hooks/tessera_guard.mjs"
HOOK_STATUS = "Tessera is checking project policy"

_EVENT_GROUPS: dict[str, dict[str, Any]] = {
    "PreToolUse": {
        "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookRead|NotebookEdit",
    },
    "PostToolUse": {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit",
    },
    "Stop": {},
    "SessionStart": {},
    "ConfigChange": {"matcher": "project_settings|local_settings|skills"},
}


def _sha(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _load_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot merge invalid {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"cannot merge {path}: top-level JSON value must be an object")
    return value


def _handler() -> dict[str, Any]:
    return {
        "type": "command",
        "command": HOOK_COMMAND,
        "args": [HOOK_ARG],
        "timeout": 5,
        "statusMessage": HOOK_STATUS,
    }


def _is_tessera_handler(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    command = handler.get("command")
    args = handler.get("args")
    if command == HOOK_COMMAND and isinstance(args, list) and HOOK_ARG in args:
        return True
    combined = " ".join([str(command or ""), *(str(item) for item in args or [] if isinstance(args, list))])
    return "tessera_guard.py" in combined or "tessera_guard.mjs" in combined


def _merge_event(hooks: dict[str, Any], event: str, group_template: dict[str, Any]) -> None:
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        raise ValueError(f"settings.hooks.{event} must be an array")

    cleaned: list[Any] = []
    for group in groups:
        if not isinstance(group, dict):
            cleaned.append(group)
            continue
        handlers = group.get("hooks")
        if not isinstance(handlers, list):
            cleaned.append(group)
            continue
        kept = [handler for handler in handlers if not _is_tessera_handler(handler)]
        if kept:
            copy = dict(group)
            copy["hooks"] = kept
            cleaned.append(copy)

    tessera_group = dict(group_template)
    tessera_group["hooks"] = [_handler()]
    cleaned.append(tessera_group)
    hooks[event] = cleaned


def merge_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a non-destructive, idempotent project settings merge."""
    merged = json.loads(json.dumps(settings))
    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("settings.hooks must be an object")
    for event, template in _EVENT_GROUPS.items():
        _merge_event(hooks, event, template)
    return merged


def _guard_source() -> bytes:
    path = Path(__file__).with_name("guard_runtime.mjs")
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise RuntimeError("packaged Tessera guard runtime is missing") from exc


def _rule_map(audit) -> bytes:
    lines = [
        "# Tessera Harden Rule-to-Hook Map",
        "",
        "This file maps requirements found in the analyzed project files to Tessera controls.",
        "Tessera does not invent owners, approvers, business meaning, or policy text that is not present in source.",
        "",
        "| Requirement | Source | Tessera status | Control | Hook / decision | Authority |",
        "|---|---|---|---|---|---|",
    ]
    for rule in audit.rules:
        text = rule.text.replace("|", "\\|")
        authority = rule.authority or "Not specified in analyzed source"
        lines.append(
            f"| {text} | `{rule.source}:{rule.line}` | **{rule.status.value}** "
            f"| `{rule.control_id or 'none'}` | `{rule.hook_event or 'none'} / {rule.decision or 'none'}` "
            f"| {authority.replace('|', '\\|')} |"
        )
    if not audit.rules:
        lines.append("| No normative requirement extracted. | — | **NOT-TECHNICALLY-ENFORCEABLE** | `TESSERA-HUMAN-001` | `none / none` | Not specified |")
    lines.extend(
        [
            "",
            "A mapping is not proof that the control fully satisfies the requirement.",
            "Run `tessera harden verify` to test the installed control. If the source does not identify an owner or approver, the output must continue to say that it is not specified.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def generated_artifacts(root: str | os.PathLike[str]) -> dict[str, bytes]:
    project = resolve_root(root)
    audit = audit_project(project)
    settings_path = _safe_project_path(project, ".claude/settings.json", field="settings path")
    settings = merge_settings(_load_settings(settings_path))
    inventory = {
        "schema_version": 3,
        "root": ".",
        "invariants": {
            "source_preserving": True,
            "invent_organization_context": False,
            "unknowns_remain_unknown": True,
            "interpretation_must_be_labeled": True,
        },
        "policy_inputs": [
            item
            for item in audit.inputs
            if item == "CLAUDE.md"
            or item == ".claude/CLAUDE.md"
            or item.startswith(".claude/rules/")
            or item.startswith("policy/")
        ],
        "rules": [rule.to_dict() for rule in audit.rules],
        "controls": [control.to_dict() for control in audit.controls],
        "installation": {
            "scope": "project",
            "settings_path": ".claude/settings.json",
            "hook_path": ".claude/hooks/tessera_guard.mjs",
            "policy_path": ".claude/tessera-policy.json",
            "events": list(_EVENT_GROUPS),
            "runtime": "node",
            "dry_run_default": True,
        },
    }
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy["generated_by"] = "tessera harden"
    policy["control_ids"] = [control.control_id for control in audit.controls]
    ignored = """# Local hardening state and evidence.\nbackups/\ninstall-manifest.json\nreceipts/\nstate/\nverification.json\nreport.md\nreport.html\nreport.json\n"""
    return {
        ".claude/hooks/tessera_guard.mjs": _guard_source(),
        ".claude/tessera-policy.json": _json_bytes(policy),
        ".claude/settings.json": _json_bytes(settings),
        ".tessera/.gitignore": ignored.encode("utf-8"),
        ".tessera/governance-inventory.json": _json_bytes(inventory),
        ".tessera/rule-to-hook-map.md": _rule_map(audit),
    }


def _atomic_write(path: Path, data: bytes, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        existing_mode = 0o755 if executable else 0o644
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp.chmod(existing_mode)
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _manifest_id() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%S.%fZ")


def _safe_project_path(project: Path, relative: str, *, field: str) -> Path:
    raw = Path(relative)
    if raw.is_absolute():
        raise ValueError(f"invalid project path: {field} must be project-relative")
    candidate = project / raw
    probe = candidate
    missing: list[str] = []
    while not probe.exists() and probe != project:
        missing.insert(0, probe.name)
        probe = probe.parent
    try:
        resolved = probe.resolve()
    except OSError as exc:
        raise ValueError(f"invalid project path: cannot resolve {field}") from exc
    if not resolved.is_relative_to(project):
        raise ValueError(f"invalid project path: {field} escapes the project root")
    final = resolved.joinpath(*missing)
    if not final.is_relative_to(project):
        raise ValueError(f"invalid project path: {field} escapes the project root")
    return final


def _restore_bytes(project: Path, changed: list[str], before: dict[str, bytes | None]) -> None:
    for rel in reversed(changed):
        target = _safe_project_path(project, rel, field="managed path")
        original = before[rel]
        if original is None:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        else:
            _atomic_write(target, original)


def apply_project(root: str | os.PathLike[str], *, write: bool = False) -> ApplyResult:
    project = resolve_root(root)
    artifacts = generated_artifacts(project)
    generated_at = utc_now()
    manifest_id = _manifest_id()
    backup_dir = _safe_project_path(project, f".tessera/backups/{manifest_id}", field="backup directory")
    targets = {rel: _safe_project_path(project, rel, field="managed path") for rel in artifacts}
    before = {rel: _read(targets[rel]) for rel in artifacts}
    action_names = {
        rel: ("unchanged" if before[rel] == data else "create" if before[rel] is None else "update")
        for rel, data in artifacts.items()
    }

    backup_paths: dict[str, str | None] = {rel: None for rel in artifacts}
    if write:
        for rel in sorted(artifacts):
            if action_names[rel] != "update":
                continue
            backup_target = _safe_project_path(project, f".tessera/backups/{manifest_id}/{rel}", field="backup path")
            original = before[rel]
            assert original is not None
            _atomic_write(backup_target, original)
            backup_paths[rel] = backup_target.relative_to(project).as_posix()

    actions = [
        FileAction(rel, action_names[rel], _sha(before[rel]), _sha(artifacts[rel]), backup_paths[rel])
        for rel in sorted(artifacts)
    ]
    result = ApplyResult(str(project), not write, generated_at, actions)
    changed_rels = [rel for rel in sorted(artifacts) if action_names[rel] in {"create", "update"}]

    if write and changed_rels:
        written: list[str] = []
        history_path = _safe_project_path(project, f".tessera/backups/{manifest_id}/install-manifest.json", field="manifest history path")
        latest_path = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")
        try:
            for rel in changed_rels:
                _atomic_write(targets[rel], artifacts[rel])
                written.append(rel)
            manifest = result.to_dict()
            manifest.update(
                {
                    "schema_version": 2,
                    "manifest_id": manifest_id,
                    "backup_dir": backup_dir.relative_to(project).as_posix(),
                    "tool": "tessera harden apply",
                    "runtime": "node",
                }
            )
            manifest_bytes = _json_bytes(manifest)
            _atomic_write(history_path, manifest_bytes)
            _atomic_write(latest_path, manifest_bytes)
            result.manifest_path = latest_path.relative_to(project).as_posix()
        except Exception:
            _restore_bytes(project, written, before)
            for manifest_file in (history_path, latest_path):
                try:
                    manifest_file.unlink()
                except FileNotFoundError:
                    pass
            raise
    elif write:
        latest_path = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")
        if latest_path.exists():
            result.manifest_path = latest_path.relative_to(project).as_posix()
    return result


def _resolve_manifest(project: Path, manifest_path: str | os.PathLike[str] | None) -> Path:
    candidate = Path(manifest_path) if manifest_path is not None else Path(".tessera/install-manifest.json")
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve()
        except OSError as exc:
            raise ValueError("install manifest must resolve inside the project root") from exc
        if not candidate.is_relative_to(project):
            raise ValueError("install manifest must be inside the project root")
    else:
        candidate = _safe_project_path(project, candidate.as_posix(), field="install manifest")
    if not candidate.exists():
        raise FileNotFoundError(f"install manifest not found: {candidate}")
    return candidate


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read install manifest: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("actions"), list):
        raise ValueError("invalid install manifest: actions array missing")
    if manifest.get("schema_version") != 2 or manifest.get("tool") != "tessera harden apply":
        raise ValueError("invalid install manifest: unsupported schema or producer")
    return manifest


def rollback_project(
    root: str | os.PathLike[str],
    *,
    manifest_path: str | os.PathLike[str] | None = None,
    write: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Preview or perform a two-phase rollback without partial conflict application."""
    project = resolve_root(root)
    manifest_file = _resolve_manifest(project, manifest_path)
    manifest = _read_manifest(manifest_file)

    backup_dir_rel = manifest.get("backup_dir")
    if not isinstance(backup_dir_rel, str) or not backup_dir_rel:
        raise ValueError("invalid install manifest: backup_dir missing")
    backup_dir = _safe_project_path(project, backup_dir_rel, field="backup_dir")
    backups_root = _safe_project_path(project, ".tessera/backups", field="backups root")
    if not backup_dir.is_relative_to(backups_root):
        raise ValueError("invalid install manifest: backup_dir is outside .tessera/backups")

    plans: list[dict[str, Any]] = []
    conflicts = 0
    restore_bytes: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    valid_hash = re.compile(r"^[0-9a-f]{64}$")
    for item in reversed(manifest["actions"]):
        if not isinstance(item, dict):
            raise ValueError("invalid install manifest: every action must be an object")
        rel = str(item.get("path") or "")
        if not rel:
            raise ValueError("invalid install manifest: action path missing")
        if rel in seen_paths:
            raise ValueError(f"invalid install manifest: duplicate action path {rel!r}")
        seen_paths.add(rel)
        target = _safe_project_path(project, rel, field="action path")
        action = str(item.get("action") or "")
        if action not in {"create", "update", "unchanged"}:
            raise ValueError(f"invalid install manifest: unsupported action {action!r}")
        before_hash = item.get("before_sha256")
        after_hash = item.get("after_sha256")
        if not isinstance(after_hash, str) or not valid_hash.fullmatch(after_hash):
            raise ValueError("invalid install manifest: malformed after_sha256")
        if before_hash is not None and (not isinstance(before_hash, str) or not valid_hash.fullmatch(before_hash)):
            raise ValueError("invalid install manifest: malformed before_sha256")
        if action == "create" and before_hash is not None:
            raise ValueError("invalid install manifest: create action has a before hash")
        if action in {"update", "unchanged"} and before_hash is None:
            raise ValueError(f"invalid install manifest: {action} action is missing a before hash")
        if action == "unchanged" and before_hash != after_hash:
            raise ValueError("invalid install manifest: unchanged action hashes differ")
        if action == "unchanged":
            plans.append({"path": rel, "action": "leave", "status": "unchanged"})
            continue

        current_sha = _sha(_read(target))
        expected_sha = after_hash
        original_sha = before_hash
        conflict: str | None = None
        if current_sha != expected_sha and not force:
            conflict = "current file differs from installed SHA"

        planned = "delete" if original_sha is None else "restore"
        if original_sha is not None:
            backup_rel = item.get("backup_path")
            if not isinstance(backup_rel, str) or not backup_rel:
                conflict = conflict or "backup path missing"
            else:
                backup_target = _safe_project_path(project, backup_rel, field="backup path")
                if not backup_target.is_relative_to(backup_dir):
                    conflict = conflict or "backup path is outside the manifest backup_dir"
                    restored = None
                else:
                    restored = _read(backup_target)
                if restored is None or _sha(restored) != original_sha:
                    conflict = conflict or "backup missing or hash mismatch"
                else:
                    restore_bytes[rel] = restored

        if conflict:
            conflicts += 1
            plans.append(
                {
                    "path": rel,
                    "action": "conflict",
                    "status": conflict,
                    "current_sha256": current_sha,
                    "expected_sha256": expected_sha,
                }
            )
        else:
            plans.append({"path": rel, "action": planned, "status": "planned"})

    if write and conflicts:
        for plan in plans:
            if plan["action"] not in {"conflict", "leave"}:
                plan["status"] = "blocked by rollback preflight"
    elif write:
        current_before = {
            plan["path"]: _read(_safe_project_path(project, plan["path"], field="action path"))
            for plan in plans
            if plan["action"] in {"delete", "restore"}
        }
        changed: list[str] = []
        try:
            for plan in plans:
                rel = plan["path"]
                target = _safe_project_path(project, rel, field="action path")
                if plan["action"] == "delete":
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
                    changed.append(rel)
                    plan["status"] = "applied"
                elif plan["action"] == "restore":
                    _atomic_write(target, restore_bytes[rel])
                    changed.append(rel)
                    plan["status"] = "applied"
            latest = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")
            if manifest_file == latest:
                try:
                    latest.unlink()
                except FileNotFoundError:
                    pass
        except Exception:
            _restore_bytes(project, changed, current_before)
            raise

    manifest_display = manifest_file.relative_to(project).as_posix()
    return {
        "schema_version": 2,
        "root": str(project),
        "dry_run": not write,
        "force": force,
        "manifest": manifest_display,
        "conflicts": conflicts,
        "ok": conflicts == 0,
        "transactional": True,
        "actions": plans,
    }
