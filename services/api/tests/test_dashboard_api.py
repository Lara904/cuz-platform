# services/api/tests/test_dashboard_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import dashboard as dashboard_router
from services.api.routers import findings as findings_router

TENANT = "acmecorp"


def _f(rule_id: str, severity: str, status: str = "open") -> Finding:
    return Finding(tenant_id=TENANT, rule_id=rule_id, severity=severity, title="t",
                   description="d", affected_nodes=[rule_id], affected_node_names=[rule_id],
                   remediation_hint="h", status=status)


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(findings_router, "_detect", lambda t: [
        _f("A", "CRITICAL"), _f("B", "HIGH"), _f("C", "HIGH", status="acknowledged")])
    monkeypatch.setattr(findings_router, "_store", {})
    monkeypatch.setattr(dashboard_router, "_node_count", lambda t: 209)
    monkeypatch.setattr(dashboard_router, "_health_score", lambda t: 0.92)

    async def fake_recent(tenant_id: str, limit: int = 20) -> list[dict]:
        return [{"finding_id": "f1", "rule_id": "IAM-001", "action": "acknowledged",
                 "actor": "alice", "created_at": "2026-10-19T10:00:00+00:00"}]
    monkeypatch.setattr(dashboard_router.audit, "recent", fake_recent)
    monkeypatch.setattr(dashboard_router, "_freshness", lambda t: [
        {"source": "entra_id", "nodes": 41, "avg_freshness": 1.0, "fresh": 41, "aging": 0, "stale": 0}])
    app = FastAPI()
    app.include_router(dashboard_router.router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('alice', Role.VIEWER, TENANT)}"}


def test_stats_counts_only_open_findings(monkeypatch):
    body = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/dashboard/stats",
                                    headers=_auth()).json()
    assert body == {"node_count": 209, "by_severity": {"CRITICAL": 1, "HIGH": 1},
                    "open": 2, "health_score": 0.92}


def test_timeline_returns_audit_events(monkeypatch):
    body = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/dashboard/timeline",
                                    headers=_auth()).json()
    assert body[0]["rule_id"] == "IAM-001" and body[0]["actor"] == "alice"


def test_freshness_passthrough(monkeypatch):
    body = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/dashboard/freshness",
                                    headers=_auth()).json()
    assert body[0]["source"] == "entra_id"


def test_dashboard_requires_auth(monkeypatch):
    client = _client(monkeypatch)
    assert client.get(f"/api/v1/tenants/{TENANT}/dashboard/stats").status_code == 401
