"""Baseline controls and policy-line classification."""
from __future__ import annotations

import hashlib
import re

from .model import Control, EnforcementStatus, Rule


BASELINE_CONTROLS: tuple[Control, ...] = (
    Control(
        control_id="TESSERA-SEC-001",
        title="Secret and protected-file guard",
        status=EnforcementStatus.ENFORCED,
        hook_event="PreToolUse",
        decision="deny",
        description="Blocks high-confidence credential material and access to protected secret files.",
        evidence="Adversarial hook fixtures exercise direct tools, shell commands, and normalized traversal paths.",
        limitations=(
            "Secret detection is pattern-based and cannot recognize every proprietary credential format.",
            "A process outside Claude Code is outside this hook's control.",
        ),
    ),
    Control(
        control_id="TESSERA-DESTRUCTIVE-001",
        title="Irreversible-operation guard",
        status=EnforcementStatus.ENFORCED,
        hook_event="PreToolUse",
        decision="deny",
        description="Blocks a narrow set of catastrophic filesystem, Git, database, infrastructure, and cloud commands.",
        evidence="Each destructive command family has positive and benign counterexample fixtures.",
        limitations=(
            "Command matching is lexical, not a complete shell parser.",
            "Novel aliases, encoded commands, or custom wrappers may evade detection.",
        ),
    ),
    Control(
        control_id="TESSERA-PROD-001",
        title="Production-operation approval gate",
        status=EnforcementStatus.REQUIRES_HUMAN_APPROVAL,
        hook_event="PreToolUse",
        decision="ask",
        description="Asks for approval when a command matches configured production markers and mutation patterns.",
        evidence="Fixtures verify that production-marked mutations ask while ordinary development commands proceed.",
        limitations=(
            "Tessera does not know who is authorized to approve unless the analyzed source states that authority.",
            "Environment naming is organization-specific; configured markers must match the organization's conventions.",
        ),
    ),
    Control(
        control_id="TESSERA-GOV-001",
        title="Governance self-modification approval gate",
        status=EnforcementStatus.REQUIRES_HUMAN_APPROVAL,
        hook_event="PreToolUse",
        decision="ask",
        description="Asks for approval before Claude Code writes to configured governance and hardening paths.",
        evidence="Direct-edit, traversal, and shell-write fixtures cover protected governance paths.",
        limitations=(
            "Tessera does not infer the owning team or approval authority from path names.",
            "ConfigChange hooks can observe external edits but cannot reverse them; this control governs Claude tool calls.",
        ),
    ),
    Control(
        control_id="TESSERA-CLOSURE-001",
        title="Unverified closure-claim warning",
        status=EnforcementStatus.WARN_ONLY,
        hook_event="PreToolUse",
        decision="ask",
        description="Flags absolute Git commit claims that do not name an independent proving signal.",
        evidence="Commit-message fixtures distinguish absolute claims from qualified or evidence-backed language.",
        limitations=(
            "Language matching cannot establish whether the named evidence is truthful or sufficient.",
        ),
    ),
    Control(
        control_id="TESSERA-TEST-001",
        title="Post-change test receipt reminder",
        status=EnforcementStatus.WARN_ONLY,
        hook_event="PostToolUse + Stop",
        decision="additionalContext",
        description="Observes successful file changes and test commands, then warns when edits are newer than the last observed test command.",
        evidence="Stateful fixtures verify change-without-test warnings and change-then-test completion.",
        limitations=(
            "A successful command exit does not prove that the selected tests were complete or meaningful.",
            "The reminder is intentionally bounded and does not trap a session in an endless Stop-hook loop.",
        ),
    ),
    Control(
        control_id="TESSERA-DRIFT-001",
        title="Installed-artifact drift warning",
        status=EnforcementStatus.WARN_ONLY,
        hook_event="SessionStart + ConfigChange",
        decision="additionalContext",
        description="Records configuration changes and warns when installed hardening artifacts no longer match the installation manifest.",
        evidence="Session-start fixtures compare installed file hashes to the rollback manifest without storing file contents.",
        limitations=(
            "The warning does not reverse external edits or replace source-control review.",
            "Project settings are excluded from strict hash matching because unrelated hook merges are legitimate.",
        ),
    ),
    Control(
        control_id="TESSERA-HUMAN-001",
        title="Unmapped policy requirement",
        status=EnforcementStatus.NOT_TECHNICALLY_ENFORCEABLE,
        hook_event="none",
        decision="none",
        description="Keeps a sourced requirement visible when Tessera has no deterministic control that faithfully implements it.",
        evidence="The inventory preserves the source text and location without inventing an organizational interpretation.",
        limitations=(
            "Tessera does not assign an owner, approver, risk category, or business meaning that is absent from source material.",
        ),
    ),
)


_NORMATIVE = re.compile(
    r"\b(must|must not|never|always|requires?|required|do not|don't|cannot|may not|should|without approval|before (?:claiming|deploying|shipping))\b",
    re.IGNORECASE,
)

_CLASSIFIERS: tuple[tuple[str, re.Pattern[str], EnforcementStatus, str, str, str, str], ...] = (
    (
        "secrets",
        re.compile(r"\b(secrets?|credentials?|api[- ]?key|access[- ]?token|private key|\.env|password)\b", re.I),
        EnforcementStatus.ENFORCED,
        "TESSERA-SEC-001",
        "PreToolUse",
        "deny",
        "Mapped by literal terms in the sourced requirement to Tessera's protected-secret control.",
    ),
    (
        "destructive-operations",
        re.compile(r"\b(destructive|irreversible|rm\s+-rf|reset\s+--hard|force[- ]?push|drop table|truncate|destroy|recursive delete)\b", re.I),
        EnforcementStatus.ENFORCED,
        "TESSERA-DESTRUCTIVE-001",
        "PreToolUse",
        "deny",
        "Mapped by literal destructive-operation terms in the sourced requirement.",
    ),
    (
        "production-approval",
        re.compile(r"\b(production|prod|deploy(?:ment)?s?|release|terraform apply|kubectl apply|helm upgrade)\b", re.I),
        EnforcementStatus.REQUIRES_HUMAN_APPROVAL,
        "TESSERA-PROD-001",
        "PreToolUse",
        "ask",
        "Mapped to an approval gate because the sourced requirement names production or deployment activity; Tessera does not infer the approver.",
    ),
    (
        "governance-change",
        re.compile(r"(CLAUDE\.md|\.claude|settings\.json|hook|\.mcp\.json|policy|governance)", re.I),
        EnforcementStatus.REQUIRES_HUMAN_APPROVAL,
        "TESSERA-GOV-001",
        "PreToolUse",
        "ask",
        "Mapped to a configuration-change approval gate from the path or governance terms present in source.",
    ),
    (
        "test-receipt",
        re.compile(r"\b(?:run|execute)\s+(?:the\s+)?tests?\b|\btests?\s+(?:must|should)\s+(?:pass|run)\b", re.I),
        EnforcementStatus.WARN_ONLY,
        "TESSERA-TEST-001",
        "PostToolUse + Stop",
        "additionalContext",
        "Mapped to observed test-command evidence. Tessera cannot infer whether the selected test suite satisfies the organization's requirement.",
    ),
    (
        "verification-claim",
        re.compile(r"\b(tests?|verify|verified|evidence|proof|complete|done|fixed|resolved|all clean|claim)\b", re.I),
        EnforcementStatus.WARN_ONLY,
        "TESSERA-CLOSURE-001",
        "PreToolUse",
        "ask",
        "Mapped to closure-claim checking from verification or completion language present in source.",
    ),
    (
        "privacy",
        re.compile(r"\b(PII|personal data|customer data|privacy|SSN|social security|credit card)\b", re.I),
        EnforcementStatus.WARN_ONLY,
        "TESSERA-SEC-001",
        "PreToolUse",
        "deny",
        "Mapped only to Tessera's narrow high-confidence data patterns; the broader sourced privacy requirement remains outside deterministic coverage.",
    ),
)


def is_normative(text: str) -> bool:
    return bool(_NORMATIVE.search(text))


def classify_rule(source: str, line: int, text: str) -> Rule:
    normalized = " ".join(text.strip().split())
    digest = hashlib.sha256(f"{source}:{line}:{normalized}".encode("utf-8")).hexdigest()[:10].upper()
    for category, pattern, status, control_id, event, decision, rationale in _CLASSIFIERS:
        if pattern.search(normalized):
            return Rule(
                rule_id=f"POL-{digest}",
                source=source,
                line=line,
                text=normalized,
                category=category,
                status=status,
                rationale=rationale,
                control_id=control_id,
                hook_event=event,
                decision=decision,
                source_kind="ORGANIZATION",
                interpretation=None,
                interpretation_status="NOT-NEEDED",
                authority=None,
                authority_status="NOT-SPECIFIED",
            )
    return Rule(
        rule_id=f"POL-{digest}",
        source=source,
        line=line,
        text=normalized,
        category="unmapped",
        status=EnforcementStatus.NOT_TECHNICALLY_ENFORCEABLE,
        rationale="No deterministic Tessera control was mapped from the words present in this sourced requirement.",
        control_id="TESSERA-HUMAN-001",
        hook_event=None,
        decision=None,
        source_kind="ORGANIZATION",
        interpretation=None,
        interpretation_status="NOT-PERFORMED",
        authority=None,
        authority_status="NOT-SPECIFIED",
    )
