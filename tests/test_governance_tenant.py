"""SEC-5: tenant-key normalization - a JSON-numeric org must not collide with the
string tenant of the same digits via SQLite TEXT affinity, and an empty/invisible
tenant is rejected outright (no silent cross-tenant write)."""
from __future__ import annotations

import pytest

from dual_log_engine.governance.chain import GovernanceChain
from dual_log_engine.governance.store import GovernanceStore, _tenant_key


def test_numeric_and_string_org_resolve_to_one_canonical_tenant():
    s = GovernanceStore(":memory:")
    c = GovernanceChain(s)
    c.append(123, {"x": 1})     # numeric org (e.g. a JSON number from a webhook body)
    c.append("123", {"x": 2})   # string org -> the SAME canonical tenant, not a second one
    assert s.orgs() == ["123"]                      # one tenant, not two colliding forms
    assert len(s.chain_rows("123")) == 2            # both entries live under the canonical key
    assert c.verify("123")["ok"] and c.verify(123)["ok"]  # chain consistent under either form


def test_empty_tenant_is_rejected():
    s = GovernanceStore(":memory:")
    with pytest.raises(ValueError):
        s.add_change("   ", "repo", None, "alice", "human", "x")  # whitespace-only tenant


def test_tenant_key_helper_is_canonical():
    assert _tenant_key(123) == "123" == _tenant_key(" 123 ")


def test_zero_width_only_org_is_rejected():
    # round-2 #7 (LOW): a zero-width-space + BOM org survives str.strip() (they are not ASCII
    # whitespace) but has no visible character, so it must not become a ghost tenant.
    s = GovernanceStore(":memory:")
    ghost = "\u200b\ufeff"  # zero-width space + BOM, written as ASCII escapes
    with pytest.raises(ValueError):
        s.add_change(ghost, "repo", None, "a", "human", "x")


def test_pipe_in_tenant_is_rejected():
    # census n100: '|' is the anchor-preimage field separator (org|seq|head_mac), so a tenant key
    # containing '|' could blur the org/seq boundary; _tenant_key must reject it outright.
    with pytest.raises(ValueError):
        _tenant_key("acme|1")
    s = GovernanceStore(":memory:")
    with pytest.raises(ValueError):
        s.add_change("a|b", "repo", None, "alice", "human", "x")


def test_set_change_findings_is_org_scoped():
    # census C2: set_change_findings must be org-scoped, so a change_id from another tenant
    # cannot be updated cross-org.
    s = GovernanceStore(":memory:")
    cid = s.add_change("acme", "api", None, "a", "claude", "s")
    s.set_change_findings("globex", cid, 5)  # wrong org -> matches 0 rows
    assert s.changes("acme")[0]["n_findings"] == 0
    s.set_change_findings("acme", cid, 5)
    assert s.changes("acme")[0]["n_findings"] == 5
