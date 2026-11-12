# services/api/tests/test_tiers_api.py
"""P2.9 : le tier est visible dans l'API (findings, export CSV, stats du dashboard)."""

import csv
import io

from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import dashboard as dashboard_router
from services.api.routers import findings as findings_router

TENANT = "acmecorp"


def _finding(rule_id: str, node: str, status: str = "open") -> Finding:
    return Finding(
        tenant_id=TENANT,
        rule_id=rule_id,
        severity="HIGH",
        title=rule_id,
        description="d",
        affected_nodes=[node],
        affected_node_names=[node],
        remediation_hint="h",
        confidence_score=0.9,
        status=status,  # type: ignore[arg-type]
    )


FINDINGS = [
    _finding("NET-001", "a"),
    _finding("K8S-PRIV-001", "b"),
    _finding("SHADOW-IT-001", "c"),
    _finding("SHADOW-IT-001", "d"),
    _finding("IAM-OPA-001", "e", status="resolved"),  # fermé : hors des stats
]


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(findings_router, "_store", {})
    monkeypatch.setattr(findings_router, "_scan_buffers", {})
    monkeypatch.setattr(findings_router, "_detect", lambda t: [f.model_copy() for f in FINDINGS])
    monkeypatch.setattr(dashboard_router, "_node_count", lambda t: 0)
    monkeypatch.setattr(dashboard_router, "_health_score", lambda t: None)
    app = FastAPI()
    app.include_router(findings_router.router)
    app.include_router(dashboard_router.router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('alice', Role.VIEWER, TENANT)}"}


def test_every_finding_returned_by_the_api_carries_its_tier(monkeypatch):
    r = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/findings/", headers=_auth())
    assert r.status_code == 200
    tiers = {f["rule_id"]: f["tier"] for f in r.json()}
    assert tiers == {"NET-001": 1, "K8S-PRIV-001": 2, "SHADOW-IT-001": 4, "IAM-OPA-001": 0}


def test_finding_detail_carries_its_tier(monkeypatch):
    client = _client(monkeypatch)
    one = client.get(f"/api/v1/tenants/{TENANT}/findings/", headers=_auth()).json()[0]
    r = client.get(f"/api/v1/tenants/{TENANT}/findings/{one['id']}", headers=_auth())
    assert r.json()["tier"] == one["tier"]


def test_csv_export_has_a_tier_column(monkeypatch):
    r = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/findings/export/csv", headers=_auth())
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {row["rule_id"]: row["tier"] for row in rows}["NET-001"] == "1"
    assert all(row["tier"] in {"0", "1", "2", "3", "4"} for row in rows)


def test_dashboard_stats_count_open_findings_by_tier(monkeypatch):
    r = _client(monkeypatch).get(f"/api/v1/tenants/{TENANT}/dashboard/stats", headers=_auth())
    assert r.status_code == 200
    assert r.json()["by_tier"] == {"1": 1, "2": 1, "4": 2}  # IAM-OPA-001 résolu : exclu
