from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "src/dual_log_engine/hardening/guard_runtime.mjs": "a4bc866fc35945aab590802a58f47450c54f1a23",
    "src/dual_log_engine/hardening/installer.py": "d60a93bcdf29ead07fa082e880c05fe15cb7f7a5",
    "src/dual_log_engine/hardening/reporting.py": "d4a7f6c459e3ea23efaf2b41f69de1c3a5e23e21",
    "src/dual_log_engine/hardening/scanner.py": "e2a19fa4d24c4a992e2bfb483345d4c171ffb559",
    "src/dual_log_engine/hardening/verification.py": "a31cc0e4dd0a400c7275abe62507a05207cce686",
    "tests/test_hardening.py": "a93416144b3b00bd646743988e69cb72e683f095",
}


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def read(rel: str) -> str:
    path = ROOT / rel
    data = path.read_bytes()
    actual = git_blob_sha(data)
    expected = EXPECTED.get(rel)
    if expected and actual != expected:
        raise SystemExit(f"refusing unexpected base for {rel}: {actual} != {expected}")
    return data.decode("utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace(text: str, old: str, new: str, *, count: int = 1, label: str) -> str:
    actual = text.count(old)
    if actual != count:
        raise SystemExit(f"{label}: expected {count} exact match(es), found {actual}")
    return text.replace(old, new)


def sub(text: str, pattern: str, replacement: str, *, count: int = 1, label: str) -> str:
    updated, actual = re.subn(pattern, replacement, text, count=count, flags=re.MULTILINE | re.DOTALL)
    if actual != count:
        raise SystemExit(f"{label}: expected {count} regex match(es), found {actual}")
    return updated


# Installer: resolve every settings, target, backup, and manifest path through
# the existing project-confinement gate before the first write.
rel = "src/dual_log_engine/hardening/installer.py"
text = read(rel)
text = replace(
    text,
    '    settings = merge_settings(_load_settings(project / ".claude" / "settings.json"))\n',
    '    settings_path = _safe_project_path(project, ".claude/settings.json", field="settings path")\n'
    '    settings = merge_settings(_load_settings(settings_path))\n',
    label="installer settings confinement",
)
text = replace(
    text,
    '    latest_path = project / ".tessera" / "install-manifest.json"\n',
    '    latest_path = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")\n',
    count=2,
    label="installer active manifest confinement",
)
text = replace(
    text,
    '    before = {rel: _read(project / rel) for rel in artifacts}\n',
    '    targets = {rel: _safe_project_path(project, rel, field="managed path") for rel in artifacts}\n'
    '    before = {rel: _read(targets[rel]) for rel in artifacts}\n',
    label="installer managed target preflight",
)
text = replace(
    text,
    '    backup_dir = project / ".tessera" / "backups" / manifest_id\n',
    '    backup_dir = _safe_project_path(\n'
    '        project, f".tessera/backups/{manifest_id}", field="backup directory"\n'
    '    )\n',
    label="installer backup directory confinement",
)
text = replace(
    text,
    '        backup_target = backup_dir / rel\n',
    '        backup_target = _safe_project_path(\n'
    '            project, f".tessera/backups/{manifest_id}/{rel}", field="backup path"\n'
    '        )\n',
    label="installer backup target confinement",
)
text = replace(
    text,
    '        for rel in changed_rels:\n'
    '            _atomic_write(project / rel, artifacts[rel])\n',
    '        for rel in changed_rels:\n'
    '            _atomic_write(targets[rel], artifacts[rel])\n',
    label="installer atomic target confinement",
)
text = replace(
    text,
    '    for rel, data in before.items():\n'
    '        target = project / rel\n',
    '    for rel, data in before.items():\n'
    '        target = _safe_project_path(project, rel, field="managed path")\n',
    label="installer failure restore confinement",
)
text = replace(
    text,
    '    latest = project / ".tessera" / "install-manifest.json"\n',
    '    latest = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")\n',
    label="rollback latest manifest confinement",
)
text = replace(
    text,
    '    backups_root = (project / ".tessera" / "backups").resolve()\n',
    '    backups_root = _safe_project_path(project, ".tessera/backups", field="backups root")\n',
    label="rollback backups root confinement",
)
write(rel, text)


# Runtime: canonicalize the root and every project-local config, receipt, state,
# manifest, and manifest-listed artifact through existing symlink ancestors.
rel = "src/dual_log_engine/hardening/guard_runtime.mjs"
text = read(rel)
text = replace(
    text,
    'function projectRoot(payload) {\n'
    '  const envRoot = process.env.CLAUDE_PROJECT_DIR;\n'
    '  const payloadRoot = typeof payload.cwd === "string" ? payload.cwd : null;\n'
    '  return path.resolve(envRoot || payloadRoot || process.cwd());\n'
    '}\n',
    'function realpathWithMissingTail(candidate) {\n'
    '  const absolute = path.resolve(candidate);\n'
    '  const tail = [];\n'
    '  let probe = absolute;\n'
    '  while (!fs.existsSync(probe)) {\n'
    '    const parent = path.dirname(probe);\n'
    '    if (parent === probe) break;\n'
    '    tail.unshift(path.basename(probe));\n'
    '    probe = parent;\n'
    '  }\n'
    '  let base;\n'
    '  try {\n'
    '    base = fs.realpathSync.native(probe);\n'
    '  } catch {\n'
    '    base = path.resolve(probe);\n'
    '  }\n'
    '  return path.resolve(base, ...tail);\n'
    '}\n\n'
    'function insideRoot(root, candidate) {\n'
    '  const relative = path.relative(root, candidate);\n'
    '  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));\n'
    '}\n\n'
    'function projectRoot(payload) {\n'
    '  const envRoot = process.env.CLAUDE_PROJECT_DIR;\n'
    '  const payloadRoot = typeof payload.cwd === "string" ? payload.cwd : null;\n'
    '  return realpathWithMissingTail(envRoot || payloadRoot || process.cwd());\n'
    '}\n',
    label="runtime canonical root",
)
text = replace(
    text,
    '    const file = path.join(root, ".claude", "tessera-policy.json");\n'
    '    const loaded = JSON.parse(fs.readFileSync(file, "utf8"));\n',
    '    const file = localProjectPath(root, ".claude/tessera-policy.json", null);\n'
    '    if (!file) return policy;\n'
    '    const loaded = JSON.parse(fs.readFileSync(file, "utf8"));\n',
    label="runtime policy confinement",
)
text = replace(
    text,
    '  let normalized = path.resolve(candidate);\n'
    '  try {\n'
    '    if (fs.existsSync(normalized)) normalized = fs.realpathSync.native(normalized);\n'
    '  } catch {\n'
    '    // Keep the lexical normalization when realpath is unavailable.\n'
    '  }\n'
    '  const relative = path.relative(root, normalized);\n'
    '  if (relative.startsWith("..") || path.isAbsolute(relative)) return normalized.replaceAll("\\\\", "/");\n'
    '  return relative.replaceAll("\\\\", "/").replace(/^\\.\\//, "");\n',
    '  const lexical = path.resolve(candidate);\n'
    '  const normalized = realpathWithMissingTail(candidate);\n'
    '  if (!insideRoot(root, normalized)) {\n'
    '    const lexicalRelative = path.relative(root, lexical);\n'
    '    if (insideRoot(root, lexical)) {\n'
    '      return lexicalRelative.replaceAll("\\\\", "/").replace(/^\\.\\//, "");\n'
    '    }\n'
    '    return normalized.replaceAll("\\\\", "/");\n'
    '  }\n'
    '  return path.relative(root, normalized).replaceAll("\\\\", "/").replace(/^\\.\\//, "");\n',
    label="runtime normalized path confinement",
)
text = replace(
    text,
    'function localProjectPath(root, selected, fallback) {\n'
    '  const candidate = path.resolve(root, String(selected || fallback));\n'
    '  const relative = path.relative(root, candidate);\n'
    '  if (relative.startsWith("..") || path.isAbsolute(relative)) return path.resolve(root, fallback);\n'
    '  return candidate;\n'
    '}\n',
    'function localProjectPath(root, selected, fallback) {\n'
    '  const choose = (value) => {\n'
    '    if (typeof value !== "string" || !value) return null;\n'
    '    const lexical = path.isAbsolute(value) ? value : path.join(root, value);\n'
    '    const candidate = realpathWithMissingTail(lexical);\n'
    '    return insideRoot(root, candidate) ? candidate : null;\n'
    '  };\n'
    '  return choose(selected) || choose(fallback);\n'
    '}\n',
    label="runtime local path confinement",
)
text = replace(
    text,
    '    const receipt = localProjectPath(root, selected, fallback);\n'
    '    ensureParent(receipt);\n',
    '    const receipt = localProjectPath(root, selected, fallback);\n'
    '    if (!receipt) return;\n'
    '    ensureParent(receipt);\n',
    label="runtime receipt confinement",
)
text = replace(
    text,
    'function sessionStatePath(root, policy, payload) {\n'
    '  const session = safeSessionId(payload.session_id);\n'
    '  return path.join(localProjectPath(root, policy.state_dir, DEFAULT_POLICY.state_dir), `${session}.json`);\n'
    '}\n\n'
    'function readState(file) {\n'
    '  try {\n'
    '    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));\n'
    '    return parsed && typeof parsed === "object" ? parsed : { change_at: null, test_at: null, reminders: 0 };\n'
    '  } catch {\n'
    '    return { change_at: null, test_at: null, reminders: 0 };\n'
    '  }\n'
    '}\n\n'
    'function writeState(file, value) {\n'
    '  try {\n'
    '    atomicJson(file, value);\n'
    '  } catch {\n'
    '    // Hooks should not break the session because local reminder state is unavailable.\n'
    '  }\n'
    '}\n',
    'function sessionStatePath(root, policy, payload) {\n'
    '  const session = safeSessionId(payload.session_id);\n'
    '  const directory = localProjectPath(root, policy.state_dir, DEFAULT_POLICY.state_dir);\n'
    '  return directory ? path.join(directory, `${session}.json`) : null;\n'
    '}\n\n'
    'function readState(file) {\n'
    '  if (!file) return { change_at: null, test_at: null, reminders: 0 };\n'
    '  try {\n'
    '    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));\n'
    '    return parsed && typeof parsed === "object" ? parsed : { change_at: null, test_at: null, reminders: 0 };\n'
    '  } catch {\n'
    '    return { change_at: null, test_at: null, reminders: 0 };\n'
    '  }\n'
    '}\n\n'
    'function writeState(file, value) {\n'
    '  if (!file) return;\n'
    '  try {\n'
    '    atomicJson(file, value);\n'
    '  } catch {\n'
    '    // Hooks should not break the session because local reminder state is unavailable.\n'
    '  }\n'
    '}\n',
    label="runtime state confinement",
)
text = replace(
    text,
    '  const manifestPath = path.join(root, ".tessera", "install-manifest.json");\n'
    '  let manifest;\n'
    '  try {\n'
    '    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));\n',
    '  const manifestPath = localProjectPath(root, ".tessera/install-manifest.json", null);\n'
    '  if (!manifestPath) return [];\n'
    '  let manifest;\n'
    '  try {\n'
    '    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));\n',
    label="runtime manifest confinement",
)
text = replace(
    text,
    '    const rel = action.path;\n'
    '    const current = sha256File(path.join(root, rel));\n',
    '    const rel = action.path;\n'
    '    const target = localProjectPath(root, rel, null);\n'
    '    const current = target ? sha256File(target) : null;\n',
    label="runtime manifest action confinement",
)
write(rel, text)


# Scanner: never read policy, settings, hook, or MCP bytes through a symlink that
# resolves outside the audited root. Report the escape as a high-severity finding.
rel = "src/dual_log_engine/hardening/scanner.py"
text = read(rel)
text = replace(
    text,
    'def _relative(root: Path, path: Path) -> str:\n'
    '    return path.relative_to(root).as_posix()\n',
    'def _confined(root: Path, path: Path) -> bool:\n'
    '    try:\n'
    '        path.resolve().relative_to(root)\n'
    '        return True\n'
    '    except (OSError, ValueError):\n'
    '        return False\n\n\n'
    'def _relative(root: Path, path: Path) -> str:\n'
    '    return path.resolve().relative_to(root).as_posix()\n\n\n'
    'def _lexical_relative(root: Path, path: Path) -> str:\n'
    '    try:\n'
    '        return path.absolute().relative_to(root).as_posix()\n'
    '    except ValueError:\n'
    '        return path.name\n',
    label="scanner confinement helpers",
)
text = replace(
    text,
    'def discover_policy_files(root: Path) -> list[Path]:\n'
    '    files: dict[str, Path] = {}\n'
    '    explicit = [root / "CLAUDE.md", root / ".claude" / "CLAUDE.md"]\n'
    '    for path in explicit:\n'
    '        if path.is_file():\n'
    '            files[_relative(root, path)] = path\n'
    '    for pattern in (".claude/rules/*.md", "policy/*.md"):\n'
    '        for path in sorted(root.glob(pattern)):\n'
    '            if path.is_file():\n'
    '                files[_relative(root, path)] = path\n'
    '    return [files[key] for key in sorted(files)]\n',
    'def discover_policy_files(root: Path) -> list[Path]:\n'
    '    files: dict[str, Path] = {}\n'
    '    explicit = [root / "CLAUDE.md", root / ".claude" / "CLAUDE.md"]\n'
    '    for path in explicit:\n'
    '        if path.is_file() and _confined(root, path):\n'
    '            files[_relative(root, path)] = path\n'
    '    for directory in (root / ".claude" / "rules", root / "policy"):\n'
    '        if not directory.is_dir() or not _confined(root, directory):\n'
    '            continue\n'
    '        for path in sorted(directory.glob("*.md")):\n'
    '            if path.is_file() and _confined(root, path):\n'
    '                files[_relative(root, path)] = path\n'
    '    return [files[key] for key in sorted(files)]\n',
    label="scanner policy discovery confinement",
)
text = replace(
    text,
    'def _iter_hardening_targets(root: Path) -> Iterable[Path]:\n'
    '    for rel in _HARDEN_TARGETS:\n'
    '        path = root / rel\n'
    '        if path.exists():\n'
    '            yield path\n'
    '    for path in sorted((root / ".claude" / "hooks").glob("*")) if (root / ".claude" / "hooks").exists() else []:\n'
    '        if path.is_file():\n'
    '            yield path\n',
    'def _iter_hardening_targets(root: Path) -> Iterable[Path]:\n'
    '    for rel in _HARDEN_TARGETS:\n'
    '        path = root / rel\n'
    '        if path.exists() and _confined(root, path):\n'
    '            yield path\n'
    '    hooks_dir = root / ".claude" / "hooks"\n'
    '    if hooks_dir.is_dir() and _confined(root, hooks_dir):\n'
    '        for path in sorted(hooks_dir.glob("*")):\n'
    '            if path.is_file() and _confined(root, path):\n'
    '                yield path\n\n\n'
    'def _security_candidates(root: Path) -> list[Path]:\n'
    '    candidates = [\n'
    '        root / "CLAUDE.md",\n'
    '        root / ".claude",\n'
    '        root / ".tessera",\n'
    '        root / "policy",\n'
    '        root / ".claude" / "CLAUDE.md",\n'
    '        root / ".claude" / "settings.json",\n'
    '        root / ".claude" / "settings.local.json",\n'
    '        root / ".mcp.json",\n'
    '        *(root / rel for rel in _HARDEN_TARGETS),\n'
    '    ]\n'
    '    for directory, pattern in (\n'
    '        (root / ".claude" / "rules", "*.md"),\n'
    '        (root / "policy", "*.md"),\n'
    '        (root / ".claude" / "hooks", "*"),\n'
    '    ):\n'
    '        if directory.is_dir() and _confined(root, directory):\n'
    '            candidates.extend(sorted(directory.glob(pattern)))\n'
    '    return candidates\n',
    label="scanner hardening target confinement",
)
text = replace(
    text,
    '    project = resolve_root(root)\n'
    '    policy_files = discover_policy_files(project)\n'
    '    inputs = [_relative(project, path) for path in policy_files]\n'
    '    findings: list[Finding] = []\n',
    '    project = resolve_root(root)\n'
    '    findings: list[Finding] = []\n'
    '    seen_unsafe: set[str] = set()\n'
    '    for candidate in _security_candidates(project):\n'
    '        if not (candidate.exists() or candidate.is_symlink()) or _confined(project, candidate):\n'
    '            continue\n'
    '        source = _lexical_relative(project, candidate)\n'
    '        if source in seen_unsafe:\n'
    '            continue\n'
    '        seen_unsafe.add(source)\n'
    '        findings.append(\n'
    '            Finding(\n'
    '                finding_id="CFG-SYMLINK-001",\n'
    '                severity=Severity.HIGH,\n'
    '                title="Configuration path escapes the project through a symlink",\n'
    '                detail=f"{source} resolves outside the audited project and was not read.",\n'
    '                source=source,\n'
    '                remediation="Replace the symlink with a project-local file or directory before installing or verifying hooks.",\n'
    '            )\n'
    '        )\n'
    '    policy_files = discover_policy_files(project)\n'
    '    inputs = [_relative(project, path) for path in policy_files]\n',
    label="scanner symlink finding",
)
text = replace(
    text,
    '    settings, settings_error = _load_json(settings_path)\n'
    '    local_settings, local_error = _load_json(local_settings_path)\n'
',
    '    settings, settings_error = _load_json(settings_path) if _confined(project, settings_path) else (None, None)\n'
    '    local_settings, local_error = (\n'
    '        _load_json(local_settings_path) if _confined(project, local_settings_path) else (None, None)\n'
    '    )\n',
    label="scanner settings read confinement",
)
text = replace(
    text,
    '    mcp, mcp_error = _load_json(mcp_path)\n',
    '    mcp, mcp_error = _load_json(mcp_path) if _confined(project, mcp_path) else (None, None)\n',
    label="scanner MCP read confinement",
)
text = replace(
    text,
    '    if settings_path.exists():\n'
    '        inputs.append(".claude/settings.json")\n'
    '    if local_settings_path.exists():\n'
    '        inputs.append(".claude/settings.local.json")\n'
    '    if mcp_path.exists():\n'
    '        inputs.append(".mcp.json")\n',
    '    if settings_path.exists() and _confined(project, settings_path):\n'
    '        inputs.append(".claude/settings.json")\n'
    '    if local_settings_path.exists() and _confined(project, local_settings_path):\n'
    '        inputs.append(".claude/settings.local.json")\n'
    '    if mcp_path.exists() and _confined(project, mcp_path):\n'
    '        inputs.append(".mcp.json")\n',
    label="scanner input confinement",
)
text = replace(
    text,
    '        if (project / rel).exists():\n'
    '            inputs.append(rel)\n',
    '        target = project / rel\n'
    '        if target.exists() and _confined(project, target):\n'
    '            inputs.append(rel)\n',
    label="scanner generated input confinement",
)
text = replace(
    text,
    '            "settings_exists": settings_path.exists(),\n'
    '            "settings_local_exists": local_settings_path.exists(),\n'
    '            "mcp_exists": mcp_path.exists(),\n',
    '            "settings_exists": settings_path.exists() and _confined(project, settings_path),\n'
    '            "settings_local_exists": local_settings_path.exists() and _confined(project, local_settings_path),\n'
    '            "mcp_exists": mcp_path.exists() and _confined(project, mcp_path),\n',
    label="scanner metadata confinement",
)
write(rel, text)


# Verification: use the same confinement gate for every artifact, receipt, and
# generated result. Unsafe configured receipt paths fall back to the safe default.
rel = "src/dual_log_engine/hardening/verification.py"
text = read(rel)
text = replace(
    text,
    'from .controls import BASELINE_CONTROLS\n'
    'from .model import VerificationCase, VerificationResult\n',
    'from .controls import BASELINE_CONTROLS\n'
    'from .installer import _safe_project_path\n'
    'from .model import VerificationCase, VerificationResult\n',
    label="verification safe path import",
)
text = replace(
    text,
    'def _artifact_paths_from_manifest(manifest: dict[str, Any]) -> list[str]:\n'
    '    paths = [".claude/hooks/tessera_guard.mjs", ".claude/tessera-policy.json", ".claude/settings.json"]\n'
    '    for action in manifest.get("actions", []):\n'
    '        if isinstance(action, dict) and isinstance(action.get("path"), str):\n'
    '            paths.append(action["path"])\n'
    '    return sorted(set(paths))\n',
    'def _artifact_paths_from_manifest(manifest: dict[str, Any]) -> list[str]:\n'
    '    paths = [".claude/hooks/tessera_guard.mjs", ".claude/tessera-policy.json", ".claude/settings.json"]\n'
    '    for action in manifest.get("actions", []):\n'
    '        if isinstance(action, dict) and isinstance(action.get("path"), str):\n'
    '            paths.append(action["path"])\n'
    '    return sorted(set(paths))\n\n\n'
    'def _confined_or_default(project: Path, selected: Any, fallback: str, *, field: str) -> Path:\n'
    '    try:\n'
    '        return _safe_project_path(project, selected, field=field)\n'
    '    except ValueError:\n'
    '        return _safe_project_path(project, fallback, field=field)\n\n\n'
    'def _safe_artifact_hashes(project: Path, paths: list[str]) -> dict[str, str | None]:\n'
    '    hashes: dict[str, str | None] = {}\n'
    '    for rel in paths:\n'
    '        try:\n'
    '            target = _safe_project_path(project, rel, field="verification artifact")\n'
    '        except ValueError:\n'
    '            hashes[rel] = None\n'
    '            continue\n'
    '        hashes[rel] = _sha_file(target)\n'
    '    return hashes\n',
    label="verification confinement helpers",
)
text = replace(
    text,
    '    hook_path = project / ".claude" / "hooks" / "tessera_guard.mjs"\n'
    '    policy_path = project / ".claude" / "tessera-policy.json"\n'
    '    manifest_path = project / ".tessera" / "install-manifest.json"\n',
    '    hook_path = _safe_project_path(project, ".claude/hooks/tessera_guard.mjs", field="hook path")\n'
    '    policy_path = _safe_project_path(project, ".claude/tessera-policy.json", field="policy path")\n'
    '    manifest_path = _safe_project_path(project, ".tessera/install-manifest.json", field="manifest path")\n',
    label="verification core path confinement",
)
text = replace(
    text,
    '    receipt_path = project / str(policy.get("verification_receipt_path", ".tessera/receipts/verification-hooks.jsonl"))\n'
    '    receipt_path.unlink(missing_ok=True)\n',
    '    receipt_path = _confined_or_default(\n'
    '        project,\n'
    '        policy.get("verification_receipt_path"),\n'
    '        ".tessera/receipts/verification-hooks.jsonl",\n'
    '        field="verification receipt path",\n'
    '    )\n'
    '    receipt_path.unlink(missing_ok=True)\n',
    label="verification receipt confinement",
)
text = replace(
    text,
    '    artifact_hashes = {\n'
    '        ".claude/hooks/tessera_guard.mjs": _sha_file(hook_path),\n'
    '        ".claude/tessera-policy.json": _sha_file(policy_path),\n'
    '        ".claude/settings.json": _sha_file(project / ".claude" / "settings.json"),\n'
    '    }\n',
    '    artifact_hashes = {\n'
    '        ".claude/hooks/tessera_guard.mjs": _sha_file(hook_path),\n'
    '        ".claude/tessera-policy.json": _sha_file(policy_path),\n'
    '        ".claude/settings.json": _sha_file(\n'
    '            _safe_project_path(project, ".claude/settings.json", field="settings path")\n'
    '        ),\n'
    '    }\n',
    label="verification settings confinement",
)
text = replace(
    text,
    '        "inventory_sha256": _sha_file(project / ".tessera" / "governance-inventory.json"),\n'
    '        "artifact_hashes": {rel: _sha_file(project / rel) for rel in _artifact_paths_from_manifest(manifest)},\n',
    '        "inventory_sha256": _sha_file(\n'
    '            _safe_project_path(project, ".tessera/governance-inventory.json", field="inventory path")\n'
    '        ),\n'
    '        "artifact_hashes": _safe_artifact_hashes(project, _artifact_paths_from_manifest(manifest)),\n',
    label="verification evidence confinement",
)
text = replace(
    text,
    '        result_path = project / ".tessera" / "verification.json"\n'
    '        result_path.parent.mkdir(parents=True, exist_ok=True)\n',
    '        result_path = _safe_project_path(project, ".tessera/verification.json", field="verification result path")\n'
    '        result_path.parent.mkdir(parents=True, exist_ok=True)\n',
    label="verification result confinement",
)
write(rel, text)


# Reporting: escaped evidence and artifact paths are absent/drifted, never read.
rel = "src/dual_log_engine/hardening/reporting.py"
text = read(rel)
text = replace(
    text,
    'from .scanner import audit_project, resolve_root\n',
    'from .installer import _safe_project_path\n'
    'from .scanner import audit_project, resolve_root\n',
    label="reporting safe path import",
)
text = replace(
    text,
    'def _sha_file(path: Path) -> str | None:\n'
    '    try:\n'
    '        return hashlib.sha256(path.read_bytes()).hexdigest()\n'
    '    except FileNotFoundError:\n'
    '        return None\n',
    'def _sha_file(path: Path) -> str | None:\n'
    '    try:\n'
    '        return hashlib.sha256(path.read_bytes()).hexdigest()\n'
    '    except (FileNotFoundError, OSError):\n'
    '        return None\n\n\n'
    'def _project_path(project: Path, rel: Any, *, field: str) -> Path | None:\n'
    '    try:\n'
    '        return _safe_project_path(project, rel, field=field)\n'
    '    except ValueError:\n'
    '        return None\n',
    label="reporting path helper",
)
text = replace(
    text,
    '    inventory = _load_optional_json(project / ".tessera" / "governance-inventory.json")\n'
    '    verification = _load_optional_json(project / ".tessera" / "verification.json")\n'
    '    manifest = _load_optional_json(project / ".tessera" / "install-manifest.json")\n',
    '    inventory_path = _project_path(project, ".tessera/governance-inventory.json", field="inventory path")\n'
    '    verification_path = _project_path(project, ".tessera/verification.json", field="verification path")\n'
    '    manifest_path = _project_path(project, ".tessera/install-manifest.json", field="manifest path")\n'
    '    inventory = _load_optional_json(inventory_path) if inventory_path else None\n'
    '    verification = _load_optional_json(verification_path) if verification_path else None\n'
    '    manifest = _load_optional_json(manifest_path) if manifest_path else None\n',
    label="reporting evidence confinement",
)
text = replace(
    text,
    '        current = _sha_file(project / rel)\n',
    '        artifact_path = _project_path(project, rel, field="verified artifact")\n'
    '        current = _sha_file(artifact_path) if artifact_path else None\n',
    label="reporting artifact confinement",
)
write(rel, text)


# Regression tests cover the installer, scanner, runtime, verifier fallback, and
# report behavior against real symlinks and traversal-bearing evidence.
rel = "tests/test_hardening.py"
text = read(rel)
text = replace(
    text,
    'import argparse\nimport json\nimport os\n',
    'import argparse\nimport hashlib\nimport json\nimport os\n',
    label="test hashlib import",
)
anchor = '\n\ndef test_packaging_includes_node_runtime():\n'
new_tests = r'''


def _symlink_directory_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable on this runner: {exc}")


def test_apply_rejects_symlinked_managed_directory_before_external_write(tmp_path):
    root = project(tmp_path)
    outside = tmp_path / "outside-claude"
    outside.mkdir()
    _symlink_directory_or_skip(root / ".claude", outside)

    with pytest.raises(ValueError, match="escapes the project root"):
        apply_project(root, write=True)

    assert list(outside.iterdir()) == []
    assert not (root / ".tessera" / "install-manifest.json").exists()


def test_audit_reports_but_does_not_read_external_symlinked_policy(tmp_path):
    root = project(tmp_path)
    outside = tmp_path / "outside-policy"
    outside.mkdir()
    sentinel = "EXTERNAL-SENTINEL-MUST-NOT-BE-READ"
    (outside / "CLAUDE.md").write_text(f"- Never expose {sentinel}.\n", encoding="utf-8")
    _symlink_directory_or_skip(root / ".claude", outside)

    payload = audit_project(root).to_dict()

    assert any(item["finding_id"] == "CFG-SYMLINK-001" for item in payload["findings"])
    assert sentinel not in json.dumps(payload)


def test_hook_does_not_follow_receipt_directory_symlink_outside_project(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    outside = tmp_path / "outside-receipts"
    outside.mkdir()
    receipts = root / ".tessera" / "receipts"
    if receipts.exists() or receipts.is_symlink():
        if receipts.is_dir() and not receipts.is_symlink():
            shutil.rmtree(receipts)
        else:
            receipts.unlink()
    _symlink_directory_or_skip(receipts, outside)

    node = shutil.which("node")
    assert node
    hook = root / ".claude" / "hooks" / "tessera_guard.mjs"
    payload = {
        "session_id": "symlink-receipt",
        "cwd": str(root),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf build"},
    }
    env = os.environ.copy()
    env["CLAUDE_PROJECT_DIR"] = str(root)
    env["TESSERA_HARDEN_VERIFICATION"] = "1"
    proc = subprocess.run(
        [node, str(hook)], input=json.dumps(payload), text=True, capture_output=True, env=env, cwd=root
    )

    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert list(outside.iterdir()) == []


def test_verify_falls_back_from_traversal_receipt_path(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    policy_path = root / ".claude" / "tessera-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["verification_receipt_path"] = "../escaped-verification.jsonl"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    verification = verify_project(root)

    assert verification["ok"] is True
    assert not (tmp_path / "escaped-verification.jsonl").exists()
    assert (root / ".tessera" / "receipts" / "verification-hooks.jsonl").exists()


def test_report_treats_traversal_artifact_as_drift_without_reading_it(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    verify_project(root)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside evidence", encoding="utf-8")
    verification_path = root / ".tessera" / "verification.json"
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    verification["artifact_hashes"]["../outside.txt"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    verification_path.write_text(json.dumps(verification), encoding="utf-8")

    payload = json.loads(render_report(root, "json"))
    escaped = next(item for item in payload["artifact_integrity"] if item["path"] == "../outside.txt")

    assert payload["verdict"] == "STALE"
    assert escaped["current_sha256"] is None
    assert escaped["match"] is False
'''
text = replace(text, anchor, new_tests + anchor, label="security regression tests")
write(rel, text)


# Document the now-enforced filesystem boundary.
for rel, old, new in (
    (
        "README.md",
        "Installation and rollback are dry-run by default. Tessera preserves unrelated\nsettings and hooks, installs a Node built-ins-only runtime",
        "Installation and rollback are dry-run by default. Tessera preserves unrelated\nsettings and hooks, refuses managed paths whose symlink resolution escapes the project, installs a Node built-ins-only runtime",
    ),
    (
        "docs/HARDENING.md",
        "- atomic writes with pre-install backups\n",
        "- atomic writes with pre-install backups\n- rejection of managed, evidence, receipt, and state paths whose symlink resolution escapes the project root\n",
    ),
):
    path = ROOT / rel
    current = path.read_text(encoding="utf-8")
    current = replace(current, old, new, label=f"documentation boundary: {rel}")
    path.write_text(current, encoding="utf-8")

print("applied project-confinement security patch")
