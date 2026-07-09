"""
tests/integration/test_api_p08.py

Tests d'intégration pour P0.8 — API Tenant management & Authentification.
Lance contre une vraie instance FastAPI + PostgreSQL (via docker-compose).

Couvre :
  - Auth mock (token valide / invalide)
  - RBAC : accès autorisé / refusé selon le rôle
  - CRUD tenants complet
  - Isolation tenant (un viewer ne voit pas les autres tenants)
  - OpenAPI accessible

Prérequis : docker compose up -d && uvicorn services.api.main:app --port 8000
"""
import pytest
pytestmark = pytest.mark.skip(reason="Tests d'intégration live — lancer manuellement avec l'API active")
import httpx

BASE_URL = "http://localhost:8000"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def get_token(username: str, password: str = "dev") -> str:
    """Obtient un JWT pour l'utilisateur donné."""
    resp = httpx.post(
        f"{BASE_URL}/auth/token",
        data={"username": username, "password": password},
    )
    assert resp.status_code == 200, f"Auth échouée pour {username}: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def token_tenant_admin():
    return get_token("admin")


@pytest.fixture(scope="module")
def token_admin():
    return get_token("admin_user")


@pytest.fixture(scope="module")
def token_operator():
    return get_token("operator_user")


@pytest.fixture(scope="module")
def token_viewer():
    return get_token("viewer_user")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Tests Health ──────────────────────────────────────────────────────────────

def test_health_check():
    """Le health check répond 200 sans authentification."""
    resp = httpx.get(f"{BASE_URL}/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_openapi_accessible():
    """L'OpenAPI auto-générée est accessible sur /docs."""
    resp = httpx.get(f"{BASE_URL}/docs")
    assert resp.status_code == 200


# ── Tests Auth ────────────────────────────────────────────────────────────────

def test_auth_token_valid():
    """Un token est retourné pour des identifiants valides."""
    resp = httpx.post(
        f"{BASE_URL}/auth/token",
        data={"username": "admin", "password": "dev"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "tenant_admin"


def test_auth_token_invalid_password():
    """Un mauvais mot de passe retourne 401."""
    resp = httpx.post(
        f"{BASE_URL}/auth/token",
        data={"username": "admin", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_protected_endpoint_without_token():
    """Un endpoint protégé sans token retourne 401."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tenants")
    assert resp.status_code == 401


def test_protected_endpoint_with_invalid_token():
    """Un token invalide retourne 401."""
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert resp.status_code == 401


# ── Tests RBAC ────────────────────────────────────────────────────────────────

def test_rbac_viewer_cannot_list_all_tenants(token_viewer):
    """Un viewer ne peut pas lister tous les tenants (tenant_admin requis)."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tenants", headers=auth_header(token_viewer))
    assert resp.status_code == 403


def test_rbac_operator_cannot_list_all_tenants(token_operator):
    """Un operator ne peut pas lister tous les tenants."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tenants", headers=auth_header(token_operator))
    assert resp.status_code == 403


def test_rbac_admin_cannot_list_all_tenants(token_admin):
    """Un admin (scope son tenant) ne peut pas lister tous les tenants."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tenants", headers=auth_header(token_admin))
    assert resp.status_code == 403


def test_rbac_tenant_admin_can_list_tenants(token_tenant_admin):
    """Un tenant_admin peut lister tous les tenants."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tenants", headers=auth_header(token_tenant_admin))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ── Tests CRUD Tenants ────────────────────────────────────────────────────────

def test_create_tenant_stellantis(token_tenant_admin):
    """Critère P0.8 : le tenant stellantis-financial est créable via l'API."""
    # Nettoyer si déjà existant
    httpx.delete(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_tenant_admin),
    )

    resp = httpx.post(
        f"{BASE_URL}/api/v1/tenants",
        headers=auth_header(token_tenant_admin),
        json={"id": "stellantis-financial", "name": "Stellantis Financial Services"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["id"] == "stellantis-financial"
    assert data["name"] == "Stellantis Financial Services"
    assert data["status"] == "active"


def test_create_tenant_duplicate_returns_409(token_tenant_admin):
    """Créer un tenant avec un ID existant retourne 409 Conflict."""
    resp = httpx.post(
        f"{BASE_URL}/api/v1/tenants",
        headers=auth_header(token_tenant_admin),
        json={"id": "stellantis-financial", "name": "Doublon"},
    )
    assert resp.status_code == 409


def test_get_tenant_as_admin(token_admin):
    """Un admin peut lire son propre tenant."""
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == "stellantis-financial"


def test_get_tenant_scope_isolation(token_viewer):
    """Un viewer ne peut pas lire un tenant auquel il n'appartient pas."""
    # viewer_user appartient à stellantis-financial, pas à acmecorp
    # D'abord créer acmecorp (si besoin)
    # On vérifie juste que le viewer ne peut pas lire le tenant d'un autre
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants/acmecorp",
        headers=auth_header(token_viewer),
    )
    # 403 (pas son tenant) ou 404 (tenant inexistant) sont tous deux acceptables
    assert resp.status_code in (403, 404)


def test_tenant_admin_can_read_any_tenant(token_tenant_admin):
    """Un tenant_admin peut lire n'importe quel tenant."""
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_tenant_admin),
    )
    assert resp.status_code == 200


def test_update_tenant(token_admin):
    """Un admin peut mettre à jour le nom de son tenant."""
    resp = httpx.put(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_admin),
        json={"name": "Stellantis Financial Services (updated)"},
    )
    assert resp.status_code == 200
    assert "updated" in resp.json()["name"]


def test_viewer_cannot_update_tenant(token_viewer):
    """Un viewer ne peut pas mettre à jour un tenant."""
    resp = httpx.put(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_viewer),
        json={"name": "Hacked"},
    )
    assert resp.status_code == 403


def test_delete_tenant_by_non_admin(token_admin):
    """Un admin (non tenant_admin) ne peut pas supprimer un tenant."""
    resp = httpx.delete(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial",
        headers=auth_header(token_admin),
    )
    assert resp.status_code == 403


def test_get_nonexistent_tenant(token_tenant_admin):
    """Accéder à un tenant inexistant retourne 404."""
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants/tenant-qui-nexiste-pas",
        headers=auth_header(token_tenant_admin),
    )
    assert resp.status_code == 404


# ── Tests Connecteurs ─────────────────────────────────────────────────────────

def test_create_connector(token_admin):
    """Un admin peut créer un connecteur pour son tenant."""
    resp = httpx.post(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial/connectors",
        headers=auth_header(token_admin),
        json={
            "type": "servicenow",
            "name": "ServiceNow CMDB Stellantis",
            "config": {"instance_url": "https://stellantis.service-now.com"},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["type"] == "servicenow"
    assert data["tenant_id"] == "stellantis-financial"
    assert data["status"] == "pending"
    return data["id"]


def test_list_connectors(token_viewer):
    """Un viewer peut lister les connecteurs de son tenant."""
    resp = httpx.get(
        f"{BASE_URL}/api/v1/tenants/stellantis-financial/connectors",
        headers=auth_header(token_viewer),
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)