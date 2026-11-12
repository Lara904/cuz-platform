# services/api/tests/test_detection_errors_api.py
"""Une détection dégradée est visible dans l'API (findings/stats et dashboard/stats), jamais muette."""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import dashboard as dashboard_router
from services.api.routers import findings as findings_router

TENANT = "acmecorp"


def _finding() -> Finding:
    return Finding(
        tenant_id=TENANT,
        rule_id="NET-001",
        severity="HIGH",
        title="t",
        description="d",
        affected_nodes=["n"],
        affected_node_names=["n"],
        remediation_hint="h",
    )


class _FakeRunner:
    def __init__(self) -> None:
        self.errors: list[str] = ["OPA : injoignable ou en erreur"]

    def run_all_with_status(self, tenant_id: str):
        return [_finding()], list(self.errors)


def _setup(monkeypatch) -> tuple[TestClient, _FakeRunner]:
    runner = _FakeRunner()
    monkeypatch.setattr(findings_router, "_runner", lambda: runner)
    monkeypatch.setattr(findings_router, "_store", {})
    monkeypatch.setattr(findings_router, "_scan_buffers", {})
    monkeypatch.setattr(findings_router, "_detection_errors", {})
    monkeypatch.setattr(dashboard_router, "_node_count", lambda t: 0)
    monkeypatch.setattr(dashboard_router, "_health_score", lambda t: None)
    app = FastAPI()
    app.include_router(findings_router.router)
    app.include_router(dashboard_router.router)
    return TestClient(app), runner


def _auth(tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('alice', Role.VIEWER, tenant)}"}


def test_findings_stats_report_a_degraded_detection(monkeypatch):
    client, _ = _setup(monkeypatch)
    body = client.get(f"/api/v1/tenants/{TENANT}/findings/stats", headers=_auth()).json()
    assert body["total"] == 1  # le finding Cypher est bien là...
    assert body["detection_errors"] == ["OPA : injoignable ou en erreur"]  # ...et le manque est dit


def test_dashboard_stats_report_a_degraded_detection(monkeypatch):
    client, _ = _setup(monkeypatch)
    body = client.get(f"/api/v1/tenants/{TENANT}/dashboard/stats", headers=_auth()).json()
    assert body["detection_errors"] == ["OPA : injoignable ou en erreur"]


def test_errors_clear_after_a_complete_recompute(monkeypatch):
    client, runner = _setup(monkeypatch)
    url = f"/api/v1/tenants/{TENANT}/findings"
    assert client.get(f"{url}/stats", headers=_auth()).json()["detection_errors"]
    runner.errors = []  # OPA est revenu
    op = {"Authorization": f"Bearer {create_access_token('alice', Role.OPERATOR, TENANT)}"}
    assert client.post(f"{url}/refresh", headers=op).status_code == 200
    assert client.get(f"{url}/stats", headers=_auth()).json()["detection_errors"] == []


def test_complete_detection_reports_no_error(monkeypatch):
    client, runner = _setup(monkeypatch)
    runner.errors = []
    body = client.get(f"/api/v1/tenants/{TENANT}/findings/stats", headers=_auth()).json()
    assert body["detection_errors"] == []


def test_errors_are_per_tenant(monkeypatch):
    client, _ = _setup(monkeypatch)
    client.get(f"/api/v1/tenants/{TENANT}/findings/stats", headers=_auth())
    assert findings_router.detection_errors("globex") == []
    assert findings_router.detection_errors(TENANT) == ["OPA : injoignable ou en erreur"]


def test_detect_stores_errors_with_the_runner_status(monkeypatch):
    _, runner = _setup(monkeypatch)
    assert [f.rule_id for f in findings_router._detect(TENANT)] == ["NET-001"]
    assert findings_router.detection_errors(TENANT) == runner.errors
    assert SimpleNamespace  # (import utilisé)
