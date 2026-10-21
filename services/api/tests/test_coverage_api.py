# services/api/tests/test_coverage_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.api.middleware.auth import Role, create_access_token
from services.api.routers import coverage as coverage_router

TENANT = "acmecorp"


def _client(monkeypatch, total: int, in_cmdb: int) -> TestClient:
    monkeypatch.setattr(coverage_router, "_counts", lambda t: (total, in_cmdb))
    app = FastAPI()
    app.include_router(coverage_router.router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('auditor', Role.VIEWER, TENANT)}"}


def test_coverage_below_100_when_unknown_nodes_exist(monkeypatch):
    body = _client(monkeypatch, 212, 155).get(f"/api/v1/tenants/{TENANT}/coverage",
                                              headers=_auth()).json()
    assert body["cmdb_coverage_pct"] == 73.1
    assert body["not_declared"] == 57
    assert body["cmdb_coverage_pct"] < 100


def test_coverage_is_null_on_empty_tenant(monkeypatch):
    body = _client(monkeypatch, 0, 0).get(f"/api/v1/tenants/{TENANT}/coverage",
                                          headers=_auth()).json()
    assert body["cmdb_coverage_pct"] is None
