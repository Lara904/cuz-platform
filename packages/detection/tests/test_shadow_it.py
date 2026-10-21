# packages/detection/tests/test_shadow_it.py
from unittest.mock import MagicMock

from packages.detection.rules import make_rule, shadow_it
from packages.detection.runner import ALL_RULE_MODULES


def test_shadow_it_rule_is_registered_in_runner():
    assert shadow_it in ALL_RULE_MODULES


def test_shadow_it_builds_medium_findings_per_node():
    session = MagicMock()
    session.run.return_value.data.return_value = [
        {"node_ids": ["minio:acmecorp-public"], "node_names": ["acmecorp-public"]}]
    findings = make_rule(shadow_it.SHADOW_IT_001)(session, "acmecorp")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SHADOW-IT-001" and f.severity == "MEDIUM"
    assert f.affected_nodes == ["minio:acmecorp-public"]
    assert "ServiceNow" in f.description


def test_shadow_it_query_excludes_cmdb_nodes_and_stays_tenant_scoped():
    cypher = shadow_it.SHADOW_IT_001.cypher
    assert "NOT 'servicenow' IN n.sources" in cypher
    assert "$tenant_id" in cypher
