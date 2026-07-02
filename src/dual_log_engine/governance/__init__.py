"""dual_log_engine.governance - org-deployable, agent-agnostic governance & safety.

Watches the *output* of AI-assisted development (git changes), runs grounded
safety checks on each change, records everything in a tamper-evident hash chain,
and produces an org-readable report. Agent-agnostic by construction: it looks at
the change a Claude / GPT / Cursor / human produced, not at the agent.

Layers:
  * ingest   - parse a diff + attribution into a change, route added lines to safety
  * safety   - grounded checks (each citing OWASP/CWE/GDPR) behind a two-signal gate
  * chain    - append-only, SHA-256 hash-chained tamper-evident ledger
  * report   - the org read (what changed, by whom, what's risky)
  * store    - SQLite tables (changes / findings / chain), org = tenant isolation
"""
from __future__ import annotations

from .chain import GovernanceChain
from .compliance import compliance_data, compliance_report
from .dashboard import dashboard_data, render_dashboard
from .ingest import Attribution, ingest_change
from .report import org_report
from .safety.engine import Finding, scan_lines
from .store import GovernanceStore

__all__ = [
    "Attribution",
    "Finding",
    "GovernanceChain",
    "GovernanceStore",
    "compliance_data",
    "compliance_report",
    "dashboard_data",
    "ingest_change",
    "org_report",
    "render_dashboard",
    "scan_lines",
]
