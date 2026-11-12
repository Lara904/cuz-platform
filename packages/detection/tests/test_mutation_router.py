# packages/detection/tests/test_mutation_router.py
import re
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.models.node import CuzNode
from packages.detection.mutation_router import (
    RULE_TRIGGERS,
    MutationRouter,
    affected_rule_ids,
    registered_rules,
)

TENANT = "acmecorp"


class _Session:
    def __init__(self, rows_by_rule: dict[str, list[dict[str, Any]]], calls: list[str]) -> None:
        self.rows_by_rule = rows_by_rule
        self.calls = calls

    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def run(self, cypher: str, **_: Any) -> "_Result":
        self.calls.append(cypher)
        rule_id = next(
            r
            for r, fn in registered_rules().items()
            if fn.spec.cypher == cypher  # type: ignore[attr-defined]
        )
        return _Result(self.rows_by_rule.get(rule_id, []))


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self.rows


def _router(
    rows: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[MutationRouter, list[str]]:
    calls: list[str] = []
    driver = SimpleNamespace(session=lambda: _Session(rows or {}, calls))
    runner = SimpleNamespace(driver=driver, _fill_confidence=lambda t, fs: None)
    return MutationRouter(runner=runner), calls  # type: ignore[arg-type]


def _node_event(
    node_type: NodeType,
    event_type: EventType = EventType.NODE_UPDATED,
    attributes: dict[str, Any] | None = None,
    tenant: str = TENANT,
) -> NormalizedEvent:
    node = CuzNode(
        tenant_id=tenant,
        node_type=node_type,
        name="n",
        confidence_score=0.9,
        freshness_score=1.0,
        sources=["test"],
        attributes=attributes or {},
    )
    return NormalizedEvent(
        event_id="e1",
        raw_event_id="r1",
        tenant_id=tenant,
        source="test",
        event_type=event_type,
        timestamp=datetime.now(UTC),
        node=node,
    )


def _edge_event(edge_type: EdgeType) -> NormalizedEvent:
    edge = CuzEdge(
        tenant_id=TENANT,
        edge_type=edge_type,
        source_id="a",
        target_id="b",
        confidence_score=0.9,
        freshness_score=1.0,
    )
    return NormalizedEvent(
        event_id="e2",
        raw_event_id="r2",
        tenant_id=TENANT,
        source="test",
        event_type=EventType.EDGE_CREATED,
        timestamp=datetime.now(UTC),
        edge=edge,
    )


# ── cohérence de la table avec les règles ───────────────────────────────────


def test_every_registered_rule_has_a_trigger_and_no_stale_entry():
    assert set(registered_rules()) == set(RULE_TRIGGERS)


def test_triggers_cover_every_type_cited_in_rule_cypher():
    """Ajouter un node_type/edge_type à une requête Cypher sans mettre à jour la table échoue."""
    for rule_id, fn in registered_rules().items():
        cypher = fn.spec.cypher  # type: ignore[attr-defined]
        trigger = RULE_TRIGGERS[rule_id]
        node_types = set(re.findall(r"node_type:\s*'(\w+)'", cypher))
        for group in re.findall(r"node_type IN \[([^\]]*)\]", cypher):
            node_types |= set(re.findall(r"'(\w+)'", group))
        edge_types = set(re.findall(r"edge_type:\s*'(\w+)'", cypher))
        assert node_types <= trigger.node_types, (rule_id, node_types - trigger.node_types)
        assert edge_types <= trigger.edge_types, (rule_id, edge_types - trigger.edge_types)


def test_trigger_types_are_real_enum_values():
    node_values = {t.value for t in NodeType}
    edge_values = {t.value for t in EdgeType}
    for rule_id, trigger in RULE_TRIGGERS.items():
        assert trigger.node_types <= node_values, rule_id
        assert trigger.edge_types <= edge_values, rule_id


# ── routage ─────────────────────────────────────────────────────────────────


def test_user_mutation_routes_iam_and_attack_path():
    ids = affected_rule_ids(_node_event(NodeType.USER))
    assert "IAM-001" in ids
    assert "ATTACK-PATH-001-PARTIAL" in ids
    assert "NET-001" not in ids


def test_edge_depends_on_routes_attack_path_only():
    assert affected_rule_ids(_edge_event(EdgeType.DEPENDS_ON)) == ["ATTACK-PATH-001-PARTIAL"]


def test_network_edge_does_not_route_node_only_rules():
    ids = affected_rule_ids(_edge_event(EdgeType.ALLOWS))
    assert ids == ["OAUTH-LATERAL-001"]


def test_storage_mutation_routes_storage_public():
    assert "STORAGE-PUBLIC-001" in affected_rule_ids(_node_event(NodeType.STORAGE))


def test_shadow_it_only_on_node_creation():
    created = affected_rule_ids(_node_event(NodeType.SERVER, EventType.NODE_CREATED))
    updated = affected_rule_ids(_node_event(NodeType.SERVER, EventType.NODE_UPDATED))
    assert "SHADOW-IT-001" in created
    assert "SHADOW-IT-001" not in updated


def test_property_triggered_rule_fires_on_attribute_key():
    ids = affected_rule_ids(_node_event(NodeType.SERVER, attributes={"plaintext_secret": True}))
    assert "CIS-010" in ids


def test_periodic_only_rule_never_routed():
    for node_type in NodeType:
        assert "CIS-004" not in affected_rule_ids(_node_event(node_type, EventType.NODE_CREATED))


def test_event_without_node_or_edge_routes_nothing():
    event = _node_event(NodeType.USER).model_copy(update={"node": None})
    assert affected_rule_ids(event) == []


# ── exécution ───────────────────────────────────────────────────────────────


def test_run_on_mutation_executes_only_routed_rules():
    router, calls = _router()
    router.run_on_mutation(TENANT, _edge_event(EdgeType.DEPENDS_ON))
    assert len(calls) == 1


def test_run_on_mutation_returns_findings_of_routed_rules():
    rows = {"IAM-001": [{"node_ids": ["entra_id:u1"], "node_names": ["djana.dev"]}]}
    router, _ = _router(rows)
    findings = router.run_on_mutation(TENANT, _node_event(NodeType.USER))
    assert [f.rule_id for f in findings] == ["IAM-001"]
    assert findings[0].affected_nodes == ["entra_id:u1"]


def test_run_on_mutation_rejects_cross_tenant_event():
    router, calls = _router()
    with pytest.raises(ValueError):
        router.run_on_mutation(TENANT, _node_event(NodeType.USER, tenant="other"))
    assert calls == []


def test_failing_rule_does_not_block_other_rules_and_is_reported():
    rows = {"ATTACK-PATH-001-PARTIAL": [{"node_ids": ["a"], "node_names": ["a"]}]}
    router, _ = _router(rows)

    def boom(session: Any, tenant_id: str) -> list:
        raise RuntimeError("neo4j down")

    boom.spec = router._rules["IAM-001"].spec  # type: ignore[attr-defined]
    router._rules["IAM-001"] = boom  # type: ignore[assignment]
    result = router.run_on_mutations(TENANT, [_node_event(NodeType.USER)])
    assert result.failed_rules == ["IAM-001"]
    assert [f.rule_id for f in result.findings] == ["ATTACK-PATH-001-PARTIAL"]


def test_batch_runs_each_rule_once():
    router, calls = _router()
    events = [_node_event(NodeType.USER) for _ in range(50)]
    result = router.run_on_mutations(TENANT, events)
    assert result.rules_run == len(calls) == 3  # IAM-001, ATTACK-PATH-001-PARTIAL, CIS-005


def test_batch_unions_rules_of_different_mutations():
    router, calls = _router()
    result = router.run_on_mutations(
        TENANT, [_node_event(NodeType.USER), _edge_event(EdgeType.ALLOWS)]
    )
    assert result.rules_run == len(calls) == 4  # + OAUTH-LATERAL-001


def test_batch_with_nothing_routed_opens_no_session():
    router, calls = _router()
    result = router.run_on_mutations(TENANT, [_node_event(NodeType.NETWORK)])
    assert result.rules_run == 0 and calls == []


def test_batch_rejects_any_cross_tenant_event_before_running():
    router, calls = _router()
    with pytest.raises(ValueError):
        router.run_on_mutations(
            TENANT, [_node_event(NodeType.USER), _node_event(NodeType.USER, tenant="other")]
        )
    assert calls == []


# ── réduction du volume de requêtes ─────────────────────────────────────────


def test_full_scan_baseline_is_derived_from_registry():
    router, _ = _router()
    assert router.full_scan_queries == len(registered_rules()) == len(RULE_TRIGGERS)


def test_reduction_is_zero_before_any_mutation():
    router, _ = _router()
    assert router.query_reduction_pct() == 0.0


def test_reduction_averages_over_all_mutations():
    router, _ = _router()
    router.run_on_mutation(TENANT, _edge_event(EdgeType.DEPENDS_ON))  # 1 requête
    router.run_on_mutation(TENANT, _edge_event(EdgeType.DEPENDS_ON))  # 1 requête
    expected = round(100 * (1 - 2 / (2 * router.full_scan_queries)), 1)
    assert router.query_reduction_pct() == expected


def test_reduction_for_sample_matches_runtime_metric():
    router, _ = _router()
    sample = [_node_event(NodeType.USER), _edge_event(EdgeType.OWNS), _node_event(NodeType.API)]
    for event in sample:
        router.run_on_mutation(TENANT, event)
    assert router.reduction_for(sample) == router.query_reduction_pct()
