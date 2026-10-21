# packages/core/scoring/tests/test_criticality.py
from datetime import UTC, datetime

from packages.core.models.enums import NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring.criticality import max_criticality_along_path, node_criticality_order


def _node(attributes: dict) -> CuzNode:
    return CuzNode(tenant_id="acmecorp", node_type=NodeType.APPLICATION, name="app",
                   confidence_score=0.9, freshness_score=1.0, sources=["servicenow"],
                   last_seen=datetime.now(UTC), attributes=attributes)


def test_node_without_criticality_returns_none():
    assert node_criticality_order(_node({})) is None


def test_node_with_null_criticality_returns_none():
    assert node_criticality_order(_node({"criticality": None})) is None


def test_node_with_all_axes_returns_max():
    assert node_criticality_order(_node({"criticality": {"D": 3, "I": 2, "C": 4, "T": 1}})) == 4


def test_partial_axes_use_only_known_values():
    assert node_criticality_order(_node({"criticality": {"D": 2, "I": None}})) == 2


def test_out_of_range_and_bool_values_are_ignored():
    assert node_criticality_order(_node({"criticality": {"D": 9, "I": True, "C": 0}})) is None


def test_path_max_all_known():
    assert max_criticality_along_path([1, 3, 2]) == 3


def test_path_max_partially_known():
    assert max_criticality_along_path([None, 2, None]) == 2


def test_path_max_nothing_known():
    assert max_criticality_along_path([None, None]) is None
