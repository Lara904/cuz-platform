# packages/detection/tests/test_cis_iac_opa.py
import json

import httpx
import pytest

from packages.detection.opa_client import POLICY_PACKAGES, OPAClient, _deny_items
from packages.detection.rules import cis, iac
from packages.detection.runner import DetectionRunner

TENANT = "acmecorp"


def test_twelve_cis_rules_defined_with_native_only_cypher():
    ids = [r.spec.rule_id for r in cis.RULES]
    assert ids == [f"CIS-{i:03d}" for i in range(1, 13)]
    for r in cis.RULES:
        assert "$tenant_id" in r.spec.cypher
        assert "CONTAINS" not in r.spec.cypher


def test_iac_drift_filters_native_property_not_tags_json():
    cypher = iac.IAC_DRIFT_001.cypher
    assert "r.iac_managed = true" in cypher
    assert "CONTAINS" not in cypher and "tags" not in cypher


def test_deny_items_accepts_object_set_and_list():
    obj = {"rule_id": "X", "severity": "LOW", "title": "t", "description": "d",
           "node_id": "n", "node_name": "n", "remediation_hint": "h"}
    assert _deny_items({json.dumps(obj, sort_keys=True): True}) == [obj]
    assert _deny_items([obj]) == [obj]
    assert _deny_items(None) == []


def test_evaluate_nodes_maps_opa_results_to_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        node = body["input"]["node"]
        if request.url.path == "/v1/data/cuz/iam/deny" and node["node_type"] == "USER":
            obj = {"rule_id": "IAM-OPA-001", "severity": "HIGH", "title": "t",
                   "description": "d", "node_id": node["id"], "node_name": node["name"],
                   "remediation_hint": "h"}
            return httpx.Response(200, json={"result": {json.dumps(obj, sort_keys=True): True}})
        return httpx.Response(200, json={})

    nodes = [{"id": "u1", "tenant_id": TENANT, "name": "djanaD", "node_type": "USER",
              "attributes": {"has_mfa": False}, "tags": {}, "owner": None}]
    client = OPAClient(transport=httpx.MockTransport(handler))
    findings = client.evaluate_nodes(nodes)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "IAM-OPA-001" and f.affected_node_names == ["djanaD"]
    assert f.tenant_id == TENANT


def test_opa_unreachable_returns_no_findings_and_does_not_raise():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    nodes = [{"id": "u1", "tenant_id": TENANT, "name": "x", "node_type": "USER",
              "attributes": {}, "tags": {}, "owner": None}]
    client = OPAClient(transport=httpx.MockTransport(handler))
    assert client.evaluate_nodes(nodes) == []


def test_policy_packages_match_rego_files():
    from pathlib import Path
    rego_pkgs = set()
    for path in Path("packages/detection/rules/opa").glob("*.rego"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("package "):
                rego_pkgs.add("cuz/" + line.split()[1].split(".")[1])
    assert rego_pkgs == set(POLICY_PACKAGES)


# ── Intégration : OPA et Neo4j live (skip si indisponibles) ─────────────────

@pytest.fixture(scope="module")
def live_findings():
    try:
        runner = DetectionRunner()
        with runner.driver.session() as s:
            s.run("RETURN 1").consume()
        httpx.get(f"{OPAClient().base_url}/health", timeout=3).raise_for_status()
    except Exception as e:
        pytest.skip(f"Neo4j ou OPA indisponible : {e}")
    return runner.run_all(TENANT)


def test_opa_iam_policy_on_live_graph(live_findings):
    names = {n for f in live_findings if f.rule_id == "IAM-OPA-001"
             for n in f.affected_node_names}
    assert {"djanaD", "svc-pipeline"} <= names


def test_iac_drift_detects_archive_bucket(live_findings):
    names = {n for f in live_findings if f.rule_id == "IAC-DRIFT-001"
             for n in f.affected_node_names}
    assert "acmecorp-archive" in names
