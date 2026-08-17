"""Data contracts for Tessera's Claude Code hardening workbench."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class EnforcementStatus(str, Enum):
    """Honest status labels used throughout inventories and reports."""

    ENFORCED = "ENFORCED"
    WARN_ONLY = "WARN-ONLY"
    NOT_TECHNICALLY_ENFORCEABLE = "NOT-TECHNICALLY-ENFORCEABLE"
    REQUIRES_HUMAN_APPROVAL = "REQUIRES-HUMAN-APPROVAL"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    source: str
    line: int
    text: str
    category: str
    status: EnforcementStatus
    rationale: str
    control_id: str | None = None
    hook_event: str | None = None
    decision: str | None = None
    source_kind: str = "ORGANIZATION"
    interpretation: str | None = None
    interpretation_status: str = "NOT-NEEDED"
    authority: str | None = None
    authority_status: str = "NOT-SPECIFIED"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: Severity
    title: str
    detail: str
    source: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    status: EnforcementStatus
    hook_event: str
    decision: str
    description: str
    evidence: str
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["limitations"] = list(self.limitations)
        return data


@dataclass
class AuditResult:
    root: str
    generated_at: str
    inputs: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 3,
            "root": self.root,
            "generated_at": self.generated_at,
            "inputs": list(self.inputs),
            "rules": [rule.to_dict() for rule in self.rules],
            "findings": [finding.to_dict() for finding in self.findings],
            "controls": [control.to_dict() for control in self.controls],
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class FileAction:
    path: str
    action: str
    before_sha256: str | None
    after_sha256: str | None
    backup_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApplyResult:
    root: str
    dry_run: bool
    generated_at: str
    actions: list[FileAction] = field(default_factory=list)
    manifest_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "root": self.root,
            "dry_run": self.dry_run,
            "generated_at": self.generated_at,
            "manifest_path": self.manifest_path,
            "actions": [action.to_dict() for action in self.actions],
        }


@dataclass(frozen=True)
class VerificationCase:
    case_id: str
    description: str
    payload: dict[str, Any]
    expected_decision: str
    expected_rule_id: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    case_id: str
    description: str
    expected_decision: str
    actual_decision: str
    passed: bool
    duration_ms: int
    return_code: int
    rule_id: str | None = None
    reason: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
