# packages/detection/tests/test_iac_tier1_extra.py
"""Règles Tier 1 complémentaires (P2.10 bis, DEC-004) : IAM-STALE-ROLE-001, NET-SSH-OPEN-001,
CERT-EXPIRED-001. Même style que test_detection.py : session Neo4j simulée, aucune base réelle."""

from unittest.mock import MagicMock

from packages.detection.models import Finding
from packages.detection.rules import iac_tier1_extra, make_rule
from packages.detection.rules.iac_tier1_extra import (
    CERT_EXPIRED_001,
    IAM_STALE_ROLE_001,
    NET_SSH_OPEN_001,
)

TENANT = "acmecorp"


def _session(rows: list[dict]) -> MagicMock:
    session = MagicMock()
    session.run.return_value.data.return_value = rows
    return session


def test_rule_count_matches_defined_rules():
    assert {r.spec.rule_id for r in iac_tier1_extra.RULES} == {
        "IAM-STALE-ROLE-001",
        "NET-SSH-OPEN-001",
        "CERT-EXPIRED-001",
    }


def test_every_cypher_filters_on_tenant_and_returns_node_lists():
    for rule in iac_tier1_extra.RULES:
        cypher = rule.spec.cypher
        assert "$tenant_id" in cypher, rule.spec.rule_id
        assert "node_ids" in cypher and "node_names" in cypher, rule.spec.rule_id


def test_no_contains_on_json_attributes():
    """FIX-3 : filtre sur un booléen natif, jamais un CONTAINS sur le blob JSON."""
    for rule in iac_tier1_extra.RULES:
        assert "CONTAINS" not in rule.spec.cypher, rule.spec.rule_id


def test_iam_stale_role_rule_builds_a_finding_per_row():
    session = _session([{"node_ids": ["role-1"], "node_names": ["stale-admin-role"]}])
    findings = make_rule(IAM_STALE_ROLE_001)(session, TENANT)
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.rule_id == "IAM-STALE-ROLE-001"
    assert finding.affected_node_names == ["stale-admin-role"]
    assert finding.tier == 1


def test_net_ssh_open_rule_builds_a_finding_per_row():
    session = _session([{"node_ids": ["net-1"], "node_names": ["ssh_open_world"]}])
    findings = make_rule(NET_SSH_OPEN_001)(session, TENANT)
    assert findings[0].rule_id == "NET-SSH-OPEN-001"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].tier == 1


def test_cert_expired_rule_builds_a_finding_per_row():
    session = _session([{"node_ids": ["cert-1"], "node_names": ["legacy.acmecorp.local"]}])
    findings = make_rule(CERT_EXPIRED_001)(session, TENANT)
    assert findings[0].rule_id == "CERT-EXPIRED-001"
    assert findings[0].tier == 1


def test_empty_result_produces_no_finding():
    session = _session([])
    assert make_rule(IAM_STALE_ROLE_001)(session, TENANT) == []
    assert make_rule(NET_SSH_OPEN_001)(session, TENANT) == []
    assert make_rule(CERT_EXPIRED_001)(session, TENANT) == []
