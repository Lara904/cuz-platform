# packages/detection/tests/test_detection.py
from unittest.mock import MagicMock

import pytest

from packages.detection.models import Finding
from packages.detection.rules import attack_path, cis, dora, iam, make_rule, network

TENANT = "acmecorp"
ALL_RULES = [r for m in [network, iam, attack_path, dora] for r in m.RULES]


def _session(rows: list[dict]) -> MagicMock:
    session = MagicMock()
    session.run.return_value.data.return_value = rows
    return session


# ── Unitaires : transformation des lignes en Finding ─────────────────────────

def test_rule_count_matches_defined_rules():
    assert {r.spec.rule_id for r in ALL_RULES} == {
        "NET-001", "STORAGE-PUBLIC-001", "K8S-PRIV-001", "IAM-001",
        "OAUTH-LATERAL-001", "ATTACK-PATH-001-PARTIAL", "DORA-THIRD-PARTY-001",
    }


def test_rule_builds_one_finding_per_row():
    session = _session([
        {"node_ids": ["a"], "node_names": ["A"]},
        {"node_ids": ["b"], "node_names": ["B"]},
    ])
    findings = make_rule(iam.IAM_001)(session, TENANT)
    assert [f.affected_nodes for f in findings] == [["a"], ["b"]]
    assert all(isinstance(f, Finding) and f.rule_id == "IAM-001" for f in findings)
    assert all(f.severity == "HIGH" and f.remediation_hint for f in findings)
    assert all(f.tenant_id == TENANT for f in findings)


def test_every_cypher_filters_on_tenant_and_returns_node_lists():
    for rule in ALL_RULES:
        cypher = rule.spec.cypher
        assert "$tenant_id" in cypher, rule.spec.rule_id
        assert "node_ids" in cypher and "node_names" in cypher, rule.spec.rule_id


def test_no_contains_on_json_attributes():
    """FIX-3 : jamais de CONTAINS sur le blob JSON."""
    for rule in ALL_RULES:
        assert "CONTAINS" not in rule.spec.cypher, rule.spec.rule_id


def test_attack_path_uses_full_name_not_package_only():
    assert "dep.name = 'qs@6.5.2'" in attack_path.ATTACK_PATH_001_PARTIAL.cypher


def test_cis_rules_loaded():
    assert len(cis.RULES) == 12


def test_rule_query_uses_tenant_parameter():
    session = _session([])
    make_rule(network.NET_001)(session, "tenant_x")
    session.run.assert_called_once()
    assert session.run.call_args.kwargs == {"tenant_id": "tenant_x"}


# ── Intégration : base Neo4j live (skip si indisponible) ────────────────────

@pytest.fixture(scope="module")
def live_findings():
    try:
        from packages.detection.runner import DetectionRunner
        runner = DetectionRunner()
        with runner.driver.session() as s:
            s.run("RETURN 1").consume()
    except Exception as e:
        pytest.skip(f"Neo4j indisponible : {e}")
    return runner.run_all(TENANT)


def _names(findings: list[Finding], rule_id: str) -> set[str]:
    return {n for f in findings if f.rule_id == rule_id for n in f.affected_node_names}


def test_attack_path_partial_detected(live_findings):
    paths = [f for f in live_findings if f.rule_id == "ATTACK-PATH-001-PARTIAL"]
    assert paths, "ATTACK-PATH-001-PARTIAL non détecté"
    assert {"qs@6.5.2", "backend"} <= set(paths[0].affected_node_names)


def test_iam_001_detects_djana_and_svc_pipeline(live_findings):
    names = _names(live_findings, "IAM-001")
    assert "djanaD" in names
    assert "svc-pipeline" in names


def test_storage_public_detects_acmecorp_public(live_findings):
    assert "acmecorp-public" in _names(live_findings, "STORAGE-PUBLIC-001")
