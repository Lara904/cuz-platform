# services/api/tests/test_exports_api.py
import csv
import io

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.api.middleware.auth import Role, create_access_token
from services.api.routers import exports as exports_router

TENANT = "acmecorp"


def _client(monkeypatch, rows: list[dict]) -> TestClient:
    monkeypatch.setattr(exports_router, "_rows", lambda t: rows)
    app = FastAPI()
    app.include_router(exports_router.router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('auditor', Role.VIEWER, TENANT)}"}


def test_csv_has_esa_columns_and_rows(monkeypatch):
    rows = [{"provider_name": "Acme-Payment-SaaS", "provider_type": "", "country": "",
             "criticality": "", "exit_plan_status": "draft", "supported_function": "",
             "contract_end_date": "", "substitutability": "", "concentration_risk": ""}]
    r = _client(monkeypatch, rows).get(f"/api/v1/tenants/{TENANT}/exports/dora/ict-register",
                                       headers=_auth())
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    parsed = list(csv.DictReader(io.StringIO(r.text)))
    assert parsed[0]["provider_name"] == "Acme-Payment-SaaS"
    assert parsed[0]["exit_plan_status"] == "draft"
    assert list(parsed[0].keys()) == exports_router.FIELDNAMES


def test_export_requires_auth(monkeypatch):
    client = _client(monkeypatch, [])
    assert client.get(f"/api/v1/tenants/{TENANT}/exports/dora/ict-register").status_code == 401


def test_export_rejects_other_tenant(monkeypatch):
    client = _client(monkeypatch, [])
    token = create_access_token("auditor", Role.VIEWER, "autre")
    r = client.get(f"/api/v1/tenants/{TENANT}/exports/dora/ict-register",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
