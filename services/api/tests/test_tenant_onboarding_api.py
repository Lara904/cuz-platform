# services/api/tests/test_tenant_onboarding_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.api.middleware.auth import Role, create_access_token
from services.api.models.tenant import TenantResponse, TenantStatus
from services.api.routers import tenant_onboarding
from services.api.routers.tenants import TenantAlreadyExistsError


def _client(monkeypatch, *, existing: bool = False) -> TestClient:
    async def _fake_insert(payload):
        if existing:
            raise TenantAlreadyExistsError(f"Le tenant '{payload.id}' existe déjà.")
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        return TenantResponse(
            id=payload.id,
            name=payload.name,
            description=payload.description,
            status=TenantStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

    monkeypatch.setattr(tenant_onboarding, "insert_tenant_row", _fake_insert)
    # Pas de KUBECONFIG_PATH/VAULT_ADDR dans l'environnement de test : les deux
    # fonctions retournent honnêtement "skipped" (voir leur propre code, pas
    # besoin de les mocker pour obtenir un comportement déterministe).
    monkeypatch.delenv("KUBECONFIG_PATH", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    app = FastAPI()
    app.include_router(tenant_onboarding.router)
    return TestClient(app)


def _auth(role: Role = Role.TENANT_ADMIN, tenant_id: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('ops', role, tenant_id)}"}


def test_onboard_requires_auth(monkeypatch):
    client = _client(monkeypatch)
    r = client.post(
        "/api/v1/tenants/onboard",
        json={"id": "acmecorp-pilot", "name": "AcmeCorp Pilot", "k8s_namespace": "acmecorp-pilot"},
    )
    assert r.status_code == 401


def test_onboard_requires_tenant_admin_role(monkeypatch):
    client = _client(monkeypatch)
    r = client.post(
        "/api/v1/tenants/onboard",
        json={"id": "acmecorp-pilot", "name": "AcmeCorp Pilot", "k8s_namespace": "acmecorp-pilot"},
        headers=_auth(Role.ADMIN, "acmecorp"),
    )
    assert r.status_code == 403


def test_onboard_creates_tenant_and_reports_real_steps(monkeypatch):
    client = _client(monkeypatch)
    r = client.post(
        "/api/v1/tenants/onboard",
        json={"id": "acmecorp-pilot", "name": "AcmeCorp Pilot", "k8s_namespace": "acmecorp-pilot"},
        headers=_auth(),
    )
    assert r.status_code == 201
    body = r.json()
    assert body["tenant_id"] == "acmecorp-pilot"
    assert body["onboarding_duration_seconds"] < 7200
    steps_by_name = {s["step"]: s for s in body["steps"]}
    assert steps_by_name["create_tenant_api"]["status"] == "done"
    # Sans KUBECONFIG_PATH/VAULT_ADDR dans l'environnement de test : "skipped",
    # jamais "done" fictif (cf. DEC-010 — jamais fabriquer un résultat).
    assert steps_by_name["provision_k8s_namespace"]["status"] == "skipped"
    assert steps_by_name["provision_vault_role"]["status"] == "skipped"
    assert steps_by_name["register_connectors"]["status"] == "pending_credentials"


def test_onboard_rejects_duplicate_tenant(monkeypatch):
    client = _client(monkeypatch, existing=True)
    r = client.post(
        "/api/v1/tenants/onboard",
        json={"id": "acmecorp", "name": "AcmeCorp", "k8s_namespace": "acmecorp"},
        headers=_auth(),
    )
    assert r.status_code == 409


def test_onboard_rejects_invalid_k8s_namespace(monkeypatch):
    client = _client(monkeypatch)
    r = client.post(
        "/api/v1/tenants/onboard",
        json={"id": "acmecorp-pilot", "name": "AcmeCorp Pilot", "k8s_namespace": "Invalid_NS!"},
        headers=_auth(),
    )
    assert r.status_code == 422
