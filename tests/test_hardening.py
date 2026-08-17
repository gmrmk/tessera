from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dual_log_engine.hardening.cli import configure_parser
from dual_log_engine.hardening.installer import apply_project, merge_settings, rollback_project
from dual_log_engine.hardening.reporting import render_report
from dual_log_engine.hardening.scanner import audit_project
from dual_log_engine.hardening.verification import verify_project


POLICY = """# Project policy

- Never read secrets or .env files.
- Do not run destructive commands such as rm -rf or git reset --hard.
- Production deployments require explicit approval.
- Changes to .claude/settings.json must be reviewed.
- Always run tests before claiming the work is fully resolved.
- Code should be elegant and easy to understand.
"""

EVENTS = {"PreToolUse", "PostToolUse", "Stop", "SessionStart", "ConfigChange"}


def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "CLAUDE.md").write_text(POLICY, encoding="utf-8")
    return root


def _managed_files(root: Path) -> list[Path]:
    return [
        root / ".claude" / "hooks" / "tessera_guard.mjs",
        root / ".claude" / "settings.json",
        root / ".claude" / "tessera-policy.json",
        root / ".tessera" / ".gitignore",
        root / ".tessera" / "governance-inventory.json",
        root / ".tessera" / "rule-to-hook-map.md",
    ]


def test_audit_extracts_all_honest_statuses(tmp_path):
    result = audit_project(project(tmp_path))
    statuses = {rule.status.value for rule in result.rules}
    assert statuses == {
        "ENFORCED",
        "REQUIRES-HUMAN-APPROVAL",
        "WARN-ONLY",
        "NOT-TECHNICALLY-ENFORCEABLE",
    }
    assert any(f.finding_id == "CFG-MISSING-001" for f in result.findings)


def test_rules_preserve_source_and_do_not_invent_org_context(tmp_path):
    result = audit_project(project(tmp_path))
    by_text = {rule.text: rule for rule in result.rules}
    production = by_text["Production deployments require explicit approval."]
    unmapped = by_text["Code should be elegant and easy to understand."]

    assert production.source == "CLAUDE.md"
    assert production.source_kind == "ORGANIZATION"
    assert production.authority is None
    assert production.authority_status == "NOT-SPECIFIED"
    assert production.interpretation is None
    assert production.interpretation_status == "NOT-NEEDED"

    assert unmapped.category == "unmapped"
    assert unmapped.interpretation is None
    assert unmapped.interpretation_status == "NOT-PERFORMED"
    assert unmapped.authority is None
    assert "business" not in unmapped.rationale.lower()
    assert "owner" not in unmapped.rationale.lower()


def test_audit_flags_disabled_hooks_mcp_authority_and_literal_credentials_without_value(tmp_path):
    root = project(tmp_path)
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(
        json.dumps({"disableAllHooks": True, "hooks": {}}), encoding="utf-8"
    )
    synthetic = "synthetic-value-that-must-not-appear"
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "node",
                        "env": {"API_TOKEN": synthetic},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    audit = audit_project(root)
    ids = {finding.finding_id for finding in audit.findings}
    assert {"CFG-DISABLED-001", "CFG-PRETOOL-001", "MCP-AUTHORITY-001", "MCP-SECRET-001"} <= ids
    assert synthetic not in json.dumps(audit.to_dict())


def test_settings_merge_is_non_destructive_cross_event_and_idempotent():
    original = {
        "permissions": {"deny": ["Read(.env)"]},
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "./existing.sh"}],
                }
            ]
        },
    }
    once = merge_settings(original)
    twice = merge_settings(once)
    assert once == twice
    assert once["permissions"] == original["permissions"]
    assert EVENTS <= set(once["hooks"])

    for event in EVENTS:
        handlers = [
            handler
            for group in once["hooks"][event]
            if isinstance(group, dict)
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        tessera = [
            handler
            for handler in handlers
            if handler.get("command") == "node"
            and "${CLAUDE_PROJECT_DIR}/.claude/hooks/tessera_guard.mjs" in handler.get("args", [])
        ]
        assert len(tessera) == 1
        assert tessera[0]["timeout"] == 5
    existing = [
        handler.get("command")
        for group in once["hooks"]["PreToolUse"]
        for handler in group.get("hooks", [])
    ]
    assert "./existing.sh" in existing


def test_apply_defaults_to_dry_run_then_writes_node_guard_and_complete_inventory(tmp_path):
    root = project(tmp_path)
    dry = apply_project(root)
    assert dry.dry_run is True
    assert not (root / ".claude" / "hooks" / "tessera_guard.mjs").exists()

    applied = apply_project(root, write=True)
    assert applied.dry_run is False
    for path in _managed_files(root):
        assert path.exists(), path
    assert (root / ".tessera" / "install-manifest.json").exists()

    settings = json.loads((root / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert EVENTS <= set(settings["hooks"])
    inventory = json.loads((root / ".tessera" / "governance-inventory.json").read_text(encoding="utf-8"))
    assert inventory["schema_version"] == 3
    assert inventory["root"] == "."
    assert inventory["invariants"] == {
        "source_preserving": True,
        "invent_organization_context": False,
        "unknowns_remain_unknown": True,
        "interpretation_must_be_labeled": True,
    }
    assert inventory["installation"]["runtime"] == "node"
    assert set(inventory["installation"]["events"]) == EVENTS
    assert str(root) not in json.dumps(inventory)
    assert all(rule["source_kind"] == "ORGANIZATION" for rule in inventory["rules"])
    assert all(rule["authority_status"] == "NOT-SPECIFIED" for rule in inventory["rules"])

    rule_map = (root / ".tessera" / "rule-to-hook-map.md").read_text(encoding="utf-8")
    assert "Not specified in analyzed source" in rule_map
    assert "does not invent owners, approvers, business meaning" in rule_map


def test_verification_breaks_every_baseline_control_with_separate_receipts(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    verification = verify_project(root)

    assert verification["ok"] is True
    assert verification["failed"] == 0
    assert verification["passed"] == verification["case_count"]
    assert verification["case_count"] >= 49
    assert verification["runtime"]["command"] == "node"
    assert verification["root"] == "."
    assert verification["manifest_id"]
    assert set(verification["artifact_hashes"]) == {
        ".claude/hooks/tessera_guard.mjs",
        ".claude/tessera-policy.json",
        ".claude/settings.json",
    }

    receipt = root / ".tessera" / "receipts" / "verification-hooks.jsonl"
    operational = root / ".tessera" / "receipts" / "hooks.jsonl"
    assert receipt.exists()
    assert not operational.exists()
    text = receipt.read_text(encoding="utf-8")
    assert '"mode":"verification"' in text
    assert "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" not in text
    assert not (root / ".tessera" / "state" / "tessera-verification.json").exists()


def test_hook_confines_configured_receipts_and_state_to_project(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    policy_path = root / ".claude" / "tessera-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy.update(
        {
            "receipt_path": "../../escaped-operational.jsonl",
            "verification_receipt_path": "../../escaped-verification.jsonl",
            "state_dir": "../../escaped-state",
        }
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    node = shutil.which("node")
    assert node
    hook = root / ".claude" / "hooks" / "tessera_guard.mjs"
    env = os.environ.copy()
    env["CLAUDE_PROJECT_DIR"] = str(root)
    env["TESSERA_HARDEN_VERIFICATION"] = "1"

    deny_payload = {
        "session_id": "confined",
        "cwd": str(root),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf build"},
    }
    proc = subprocess.run(
        [node, str(hook)], input=json.dumps(deny_payload), text=True, capture_output=True, env=env, cwd=root
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    post_payload = {
        "session_id": "confined",
        "cwd": str(root),
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(root / "app.py"), "content": "x = 1"},
        "tool_response": {"ok": True},
    }
    subprocess.run([node, str(hook)], input=json.dumps(post_payload), text=True, check=True, env=env, cwd=root)

    assert not (tmp_path / "escaped-operational.jsonl").exists()
    assert not (tmp_path / "escaped-verification.jsonl").exists()
    assert not (tmp_path / "escaped-state").exists()
    assert (root / ".tessera" / "receipts" / "verification-hooks.jsonl").exists()
    assert (root / ".tessera" / "state" / "confined.json").exists()


def test_report_is_human_source_led_and_proves_current_hashes(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    verify_project(root)

    markdown = render_report(root, "markdown")
    html = render_report(root, "html")
    payload = json.loads(render_report(root, "json"))

    assert "Tessera Harden Evidence Report" in markdown
    assert "**Verdict:** **PASS**" in markdown
    assert "## Requirements" in markdown
    assert "**Requirement:** Production deployments require explicit approval." in markdown
    assert "**Authority:** Not specified in analyzed source" in markdown
    assert "**Interpretation:** NOT-NEEDED" in markdown
    assert "Installed artifact integrity" in markdown
    assert "Adversarial verification" in markdown
    assert "stakeholder" not in markdown.lower()
    assert "security team" not in markdown.lower()
    assert "business owner" not in markdown.lower()

    assert html.startswith("<!doctype html>")
    assert "Requirements" in html
    assert "Not specified in analyzed source" in html
    assert "Evidence, not assurances" not in html
    assert "class=\"cards\"" not in html

    assert payload["schema_version"] == 3
    assert payload["verdict"] == "PASS"
    assert payload["reporting_invariants"]["invent_organization_context"] is False
    assert payload["summary"]["verification_failed"] == 0
    assert payload["summary"]["verification_current"] is True
    assert payload["summary"]["manifest_current"] is True
    assert payload["summary"]["requirements_reviewed"] == 6
    assert "not specified" in " ".join(payload["evidence_gaps"]).lower()
    assert "not a penetration test" in payload["disclaimer"]


def test_report_marks_green_but_changed_installation_stale(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    verify_project(root)
    hook = root / ".claude" / "hooks" / "tessera_guard.mjs"
    hook.write_text(hook.read_text(encoding="utf-8") + "\n// drift\n", encoding="utf-8")

    payload = json.loads(render_report(root, "json"))
    assert payload["verdict"] == "STALE"
    assert payload["summary"]["verification_ok"] is True
    assert payload["summary"]["verification_current"] is False
    assert any("differ" in gap for gap in payload["evidence_gaps"])


def test_rollback_restores_existing_settings_removes_created_files_and_latest_manifest(tmp_path):
    root = project(tmp_path)
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir()
    original = b'{"permissions":{"deny":["Bash(rm *)"]}}\n'
    settings.write_bytes(original)

    apply_project(root, write=True)
    preview = rollback_project(root)
    assert preview["ok"] is True
    assert settings.read_bytes() != original

    result = rollback_project(root, write=True)
    assert result["ok"] is True
    assert result["transactional"] is True
    assert settings.read_bytes() == original
    assert not (root / ".tessera" / "install-manifest.json").exists()
    for path in _managed_files(root):
        if path == settings:
            continue
        assert not path.exists(), path


def test_rollback_conflict_preflight_is_all_or_nothing(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    hook = root / ".claude" / "hooks" / "tessera_guard.mjs"
    hook.write_text(hook.read_text(encoding="utf-8") + "\n// local edit\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in _managed_files(root)}

    result = rollback_project(root, write=True)

    assert result["ok"] is False
    assert result["conflicts"] == 1
    assert result["transactional"] is True
    assert any(item["status"] == "blocked by rollback preflight" for item in result["actions"])
    assert {path: path.read_bytes() for path in _managed_files(root)} == before
    assert (root / ".tessera" / "install-manifest.json").exists()


def test_rollback_rejects_manifest_path_traversal_before_touching_files(tmp_path):
    root = project(tmp_path)
    apply_project(root, write=True)
    manifest_path = root / ".tessera" / "install-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["actions"][0]["path"] = "../../outside.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    managed_before = {path: path.read_bytes() for path in _managed_files(root)}

    with pytest.raises(ValueError, match="escapes the project root"):
        rollback_project(root, write=True)

    assert {path: path.read_bytes() for path in _managed_files(root)} == managed_before


def test_atomic_install_preserves_existing_settings_mode(tmp_path):
    root = project(tmp_path)
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text("{}\n", encoding="utf-8")
    settings.chmod(0o640)
    expected_mode = settings.stat().st_mode & 0o777
    apply_project(root, write=True)
    assert settings.stat().st_mode & 0o777 == expected_mode


def test_second_apply_is_true_noop_and_preserves_rollback_manifest(tmp_path):
    root = project(tmp_path)
    first = apply_project(root, write=True)
    manifest = root / ".tessera" / "install-manifest.json"
    before = manifest.read_bytes()

    second = apply_project(root, write=True)

    assert first.manifest_path == ".tessera/install-manifest.json"
    assert second.manifest_path == ".tessera/install-manifest.json"
    assert all(action.action == "unchanged" for action in second.actions)
    assert manifest.read_bytes() == before


def test_audit_detects_partial_tessera_registration(tmp_path):
    root = project(tmp_path)
    (root / ".claude" / "hooks").mkdir(parents=True)
    (root / ".claude" / "hooks" / "tessera_guard.mjs").write_text("", encoding="utf-8")
    (root / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "node",
                                    "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/tessera_guard.mjs"],
                                }
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    findings = {item.finding_id: item for item in audit_project(root).findings}
    assert "CFG-TESSERA-PARTIAL-001" in findings
    assert "SessionStart" in findings["CFG-TESSERA-PARTIAL-001"].detail


def test_audit_validates_structured_hook_args(tmp_path):
    root = project(tmp_path)
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "node",
                                    "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/missing.mjs"],
                                }
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    ids = {finding.finding_id for finding in audit_project(root).findings}
    assert "CFG-BROKEN-PATH-001" in ids


def test_nested_cli_surface_accepts_explicit_break_each_rule_flag(tmp_path, capsys):
    root = project(tmp_path)
    parser = argparse.ArgumentParser(prog="tessera")
    sub = parser.add_subparsers(dest="cmd", required=True)
    harden = sub.add_parser("harden")
    configure_parser(harden)

    args = parser.parse_args(["harden", "apply", str(root), "--write"])
    assert args.func(args) == 0
    capsys.readouterr()
    args = parser.parse_args(["harden", "verify", str(root), "--break-each-rule", "--json"])
    assert args.func(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["case_count"] >= 49


def test_invalid_settings_fail_before_any_write(tmp_path):
    root = project(tmp_path)
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot merge invalid"):
        apply_project(root, write=True)
    assert not (root / ".claude" / "hooks" / "tessera_guard.mjs").exists()
    assert not (root / ".tessera" / "install-manifest.json").exists()


def test_packaging_includes_node_runtime():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert '"dual_log_engine.hardening" = ["guard_runtime.mjs"]' in text
