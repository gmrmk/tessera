"""Grounding freshness gate - the trust tree must not rot into citation theater."""
from __future__ import annotations

import pytest

from dual_log_engine.governance.safety import grounding as G


def test_every_entry_has_last_verified():
    assert G.GROUNDING and all("last_verified" in g for g in G.GROUNDING.values())


def test_stale_flags_only_entries_past_cadence():
    reg = {"old": {"last_verified": "2026-01-01"}, "fresh": {"last_verified": "2026-06-15"}}
    assert G.stale("2026-06-29", registry=reg) == ["old"]  # old ~179d > 90; fresh ~14d


def test_assert_fresh_raises_when_stale_and_passes_when_fresh():
    with pytest.raises(G.StaleGroundingError):
        G.assert_fresh("2026-06-29", registry={"old": {"last_verified": "2020-01-01"}})
    G.assert_fresh("2026-06-29", registry={"x": {"last_verified": "2026-06-01"}})  # no raise


def test_real_registry_dates_parse_and_run():
    # Evaluate against the newest verification date -> nothing is >90d behind it.
    newest = max(g["last_verified"] for g in G.GROUNDING.values())
    assert G.stale(newest) == []
