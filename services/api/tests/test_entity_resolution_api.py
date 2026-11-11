# services/api/tests/test_entity_resolution_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.api.middleware.auth import Role, create_access_token
from services.api.routers import entity_resolution as er_router

TENANT = "acmecorp"
URL = f"/api/v1/tenants/{TENANT}/entity-resolution/stats"


def _client(monkeypatch, stats: dict | None) -> TestClient:
    monkeypatch.setattr(er_router, "_stats", lambda t: stats)
    app = FastAPI()
    app.include_router(er_router.router)
    return TestClient(app)


def _auth(tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('auditor', Role.VIEWER, tenant)}"}


def test_stats_returned(monkeypatch):
    stats = {"tenant_id": TENANT, "total_nodes": 284, "auto_merge_pairs": 0,
             "pending_review_pairs": 0, "duplicate_rate_pct": 0.0,
             "duplicate_rate_basis": "estimated_from_model"}
    r = _client(monkeypatch, stats).get(URL, headers=_auth())
    assert r.status_code == 200 and r.json() == stats


def test_stats_409_when_model_not_trained(monkeypatch):
    assert _client(monkeypatch, None).get(URL, headers=_auth()).status_code == 409


def test_stats_requires_auth(monkeypatch):
    assert _client(monkeypatch, {}).get(URL).status_code in (401, 403)


def test_stats_refuses_other_tenant(monkeypatch):
    assert _client(monkeypatch, {}).get(URL, headers=_auth("other")).status_code == 403
