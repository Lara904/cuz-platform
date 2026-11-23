# services/api/tests/test_dora_compliance_api.py
"""Router dora_compliance (P2.13, DEC-008). Même style que test_exports_api.py :
monkeypatch des fonctions qui touchent Neo4j, aucune base réelle."""

import csv
import io

from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import dora_compliance as dora_router
from services.api.routers import exports as exports_router

TENANT = "acmecorp"


def _client(
    monkeypatch, *, register_rows=None, concentration_findings=None, ict_rows=None
) -> TestClient:
    monkeypatch.setattr(dora_router, "_register_rows", lambda t: register_rows or [])
    monkeypatch.setattr(
        dora_router, "_concentration_findings", lambda t: concentration_findings or []
    )
    monkeypatch.setattr(dora_router, "_ict_rows", lambda t: ict_rows or [])
    app = FastAPI()
    app.include_router(dora_router.router)
    return TestClient(app)


def _auth(tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('auditor', Role.VIEWER, tenant)}"}


# ── /register ────────────────────────────────────────────────────────────────


def test_register_returns_full_provider_rows(monkeypatch):
    rows = [
        {
            "provider_name": "Acme-Payment-SaaS",
            "provider_type": "SaaS",
            "exit_plan_status": "NOT_SET",
            "last_review_date": "",
            "supported_functions": ["Paiement client", "Facturation", "Onboarding fournisseur"],
        }
    ]
    r = _client(monkeypatch, register_rows=rows).get(
        f"/api/v1/tenants/{TENANT}/compliance/dora/register", headers=_auth()
    )
    assert r.status_code == 200
    body = r.json()
    assert body["register"] == rows
    assert len(body["register"][0]["supported_functions"]) == 3


def test_register_requires_auth(monkeypatch):
    client = _client(monkeypatch)
    assert client.get(f"/api/v1/tenants/{TENANT}/compliance/dora/register").status_code == 401


def test_register_rejects_other_tenant(monkeypatch):
    client = _client(monkeypatch)
    r = client.get(
        f"/api/v1/tenants/{TENANT}/compliance/dora/register", headers=_auth("autre-tenant")
    )
    assert r.status_code == 403


# ── /concentration-risk ──────────────────────────────────────────────────────


def _finding() -> dict:
    return Finding(
        tenant_id=TENANT,
        rule_id="DORA-CONCENTRATION-001",
        severity="HIGH",
        title="Risque de concentration ICT tiers (DORA Art. 29)",
        description="d",
        affected_nodes=["tp1"],
        affected_node_names=["Acme-Payment-SaaS"],
        remediation_hint="h",
        metadata={"critical_functions_count": 3},
    ).model_dump()


def test_concentration_risk_returns_findings(monkeypatch):
    r = _client(monkeypatch, concentration_findings=[_finding()]).get(
        f"/api/v1/tenants/{TENANT}/compliance/dora/concentration-risk", headers=_auth()
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["rule_id"] == "DORA-CONCENTRATION-001"
    assert body["findings"][0]["tier"] == 4


def test_concentration_risk_requires_auth(monkeypatch):
    client = _client(monkeypatch)
    assert (
        client.get(f"/api/v1/tenants/{TENANT}/compliance/dora/concentration-risk").status_code
        == 401
    )


# ── /export/esa ──────────────────────────────────────────────────────────────


def test_export_esa_reuses_the_same_csv_as_p1_15_export(monkeypatch):
    """DEC-008 : un seul schéma CSV « format ESA », jamais un second divergent."""
    rows = [
        {
            "provider_name": "Acme-Payment-SaaS",
            "provider_type": "SaaS",
            "country": "",
            "criticality": "critical",
            "exit_plan_status": "draft",
            "supported_function": "Paiement client",
            "contract_end_date": "",
            "substitutability": "",
            "concentration_risk": "",
        }
    ]
    r = _client(monkeypatch, ict_rows=rows).get(
        f"/api/v1/tenants/{TENANT}/compliance/dora/export/esa", headers=_auth()
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    parsed = list(csv.DictReader(io.StringIO(r.text)))
    assert parsed[0]["provider_name"] == "Acme-Payment-SaaS"
    assert list(parsed[0].keys()) == exports_router.FIELDNAMES


def test_export_esa_requires_auth(monkeypatch):
    client = _client(monkeypatch)
    assert client.get(f"/api/v1/tenants/{TENANT}/compliance/dora/export/esa").status_code == 401


def test_export_esa_rejects_other_tenant(monkeypatch):
    client = _client(monkeypatch)
    r = client.get(
        f"/api/v1/tenants/{TENANT}/compliance/dora/export/esa", headers=_auth("autre-tenant")
    )
    assert r.status_code == 403
