"""LightRAGGraphStore  -  incremental merge, typed multi-edges, pre-filtered views."""
from __future__ import annotations

import networkx as nx

from dual_log_engine.envelope import Entity, Relation
from dual_log_engine.graph_store import LightRAGGraphStore


def _entity(name, level="LOW", desc="d", etype="COMPONENT") -> Entity:
    return Entity(entity_name=name, entity_type=etype, description=desc, level=level)


def _relation(src, tgt, rtype="CAUSES", level="LOW", desc="d", weight=1) -> Relation:
    return Relation(source=src, target=tgt, relation_type=rtype, description=desc, weight=weight, level=level)


def test_upsert_entity_inserts_node_with_attributes():
    s = LightRAGGraphStore()
    s.upsert_entity("t", "r", _entity("auth.py", desc="login path"))
    node = s.entity("t", "r", "auth.py")
    assert node["entity_name"] == "auth.py"
    assert node["level"] == "LOW"
    assert node["tenant_id"] == "t" and node["repo_id"] == "r"


def test_reingesting_entity_blends_description_and_elevates_level():
    s = LightRAGGraphStore()
    s.upsert_entity("t", "r", _entity("auth.py", level="LOW", desc="first sighting"))
    s.upsert_entity("t", "r", _entity("auth.py", level="HIGH", desc="recurring risk"))
    node = s.entity("t", "r", "auth.py")
    assert node["level"] == "HIGH"  # tier is monotonic upward
    assert "first sighting" in node["description"] and "recurring risk" in node["description"]


def test_elevation_is_monotonic_high_does_not_drop_back_to_low():
    s = LightRAGGraphStore()
    s.upsert_entity("t", "r", _entity("x", level="HIGH"))
    s.upsert_entity("t", "r", _entity("x", level="LOW"))
    assert s.entity("t", "r", "x")["level"] == "HIGH"


def test_duplicate_relation_increments_weight_and_blends_description():
    s = LightRAGGraphStore()
    s.upsert_relation("t", "r", _relation("a", "b", desc="first"))
    s.upsert_relation("t", "r", _relation("a", "b", desc="second"))
    edge = s.relation("t", "r", "a", "b", "CAUSES")
    assert edge["weight"] == 2
    assert "first" in edge["description"] and "second" in edge["description"]


def test_different_relation_types_between_same_pair_coexist():
    s = LightRAGGraphStore()
    s.upsert_relation("t", "r", _relation("a", "b", rtype="CAUSES"))
    s.upsert_relation("t", "r", _relation("a", "b", rtype="RESOLVES"))
    assert s.relation("t", "r", "a", "b", "CAUSES") is not None
    assert s.relation("t", "r", "a", "b", "RESOLVES") is not None
    # MultiDiGraph keeps both typed edges rather than collapsing to one
    assert s.g.number_of_edges() == 2


def test_query_subgraph_isolates_by_tenant_and_repo():
    s = LightRAGGraphStore()
    s.upsert_entity("acme", "api", _entity("shared-name"))
    s.upsert_entity("globex", "api", _entity("shared-name"))
    view = s.query_subgraph("acme", "api")
    names = {view.nodes[n]["tenant_id"] for n in view.nodes}
    assert names == {"acme"}  # zero leakage from globex despite identical entity_name


def test_query_subgraph_filters_by_level():
    s = LightRAGGraphStore()
    s.upsert_entity("t", "r", _entity("low1", level="LOW"))
    s.upsert_entity("t", "r", _entity("high1", level="HIGH"))
    low_names = {s.g.nodes[n]["entity_name"] for n in s.query_subgraph("t", "r", level="LOW").nodes}
    high_names = {s.g.nodes[n]["entity_name"] for n in s.query_subgraph("t", "r", level="HIGH").nodes}
    assert low_names == {"low1"}
    assert high_names == {"high1"}


def test_query_subgraph_is_a_lazy_view_not_a_snapshot():
    # Proves "no destructive rebuild": the view reflects the live graph. A node
    # added after the view is created still shows up through the view.
    s = LightRAGGraphStore()
    view = s.query_subgraph("t", "r")
    assert view.number_of_nodes() == 0
    s.upsert_entity("t", "r", _entity("late"))
    assert view.number_of_nodes() == 1  # lazy view, not a copy taken at call time
