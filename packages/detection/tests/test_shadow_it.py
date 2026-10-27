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


def test_runner_drops_cloud_alert_duplicating_cypher_rule(monkeypatch):
    """Critère P2.2 : un rule_id déjà remonté par Cypher/OPA ne donne pas de finding cloud."""
    from packages.detection import runner as runner_mod
    from packages.detection.models import Finding
    cypher = Finding(tenant_id="acmecorp", rule_id="IAM-001", severity="HIGH", title="t",
                     description="d", affected_nodes=["u1"], affected_node_names=["u1"],
                     remediation_hint="h")

    class FakeSession:
        def run(self, *a, **k):
            class R:
                def data(self_inner):
                    return [
                        {"id": "cloud_detection:a1", "name": "dup", "attributes":
                         '{"rule_id": "IAM-001", "severity": "HIGH"}'},
                        {"id": "cloud_detection:a2", "name": "new", "attributes":
                         '{"rule_id": "SIM-CLOUD-001", "severity": "MEDIUM"}'},
                    ]
            return R()

    class FakeDriver:
        def session(self):
            class Ctx:
                def __enter__(self_inner):
                    return FakeSession()
                def __exit__(self_inner, *a):
                    return False
            return Ctx()

    r = object.__new__(runner_mod.DetectionRunner)
    r.driver = FakeDriver()
    out = r.run_cloud_alerts("acmecorp", {cypher.rule_id})
    assert [f.rule_id for f in out] == ["SIM-CLOUD-001"]
