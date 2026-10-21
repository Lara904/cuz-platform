# services/api/tests/test_graph_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import findings as findings_router
from services.api.routers import graph as graph_router

TENANT = "acmecorp"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(graph_router, "_query", lambda t: (
        [{"id": "u1", "name": "djanaD", "node_type": "USER", "sources": ["entra_id"],
          "confidence_score": 0.95, "freshness_score": 1.0, "owner": None,
          "attributes": {"has_mfa": False}}],
        [{"id": "e1", "source_id": "u1", "target_id": "r1", "edge_type": "OWNS",
          "confidence_score": 0.99}]))
    monkeypatch.setattr(findings_router, "_detect", lambda t: [
        Finding(tenant_id=TENANT, rule_id="ATTACK-PATH-001-PARTIAL", severity="CRITICAL",
                title="t", description="d", affected_nodes=["u1", "r1"],
                affected_node_names=["djanaD", "backend"], remediation_hint="h")])
    monkeypatch.setattr(findings_router, "_store", {})
    app = FastAPI()
    app.include_router(graph_router.router)
    return TestClient(app)


def test_graph_returns_nodes_edges_and_open_findings(monkeypatch):
    client = _client(monkeypatch)
    token = create_access_token("alice", Role.VIEWER, TENANT)
    body = client.get(f"/api/v1/tenants/{TENANT}/graph/",
                      headers={"Authorization": f"Bearer {token}"}).json()
    assert body["nodes"][0]["attributes"] == {"has_mfa": False}
    assert body["edges"][0]["edge_type"] == "OWNS"
    assert body["findings"][0]["rule_id"] == "ATTACK-PATH-001-PARTIAL"
    assert body["findings"][0]["affected_nodes"] == ["u1", "r1"]


def test_graph_requires_auth(monkeypatch):
    assert _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/graph/").status_code == 401
