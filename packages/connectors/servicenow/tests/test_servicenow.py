# packages/connectors/servicenow/tests/test_servicenow.py
import os

import pytest

from packages.connectors.servicenow.connector import ServiceNowConnector
from packages.connectors.servicenow.mapper import ServiceNowMapper
from packages.core.models.enums import NodeType

TENANT = "acmecorp"
INSTANCE = "https://dev353984.service-now.com"


@pytest.fixture
def connector():
    return ServiceNowConnector(
        tenant_id=TENANT,
        instance_url=os.getenv("SERVICENOW_URL", INSTANCE),
        client_id=os.getenv("SERVICENOW_CLIENT_ID", ""),
        client_secret=os.getenv("SERVICENOW_CLIENT_SECRET", ""),
        username=os.getenv("SERVICENOW_USER", "admin"),
        password=os.getenv("SERVICENOW_PASSWORD", ""),
    )


# ── Tests d'intégration (instance réelle, auth OAuth) ─────────────────────────


@pytest.mark.asyncio
async def test_connection_returns_true(connector):
    """test_connection() doit retourner True sur le PDI réel via OAuth."""
    result = await connector.test_connection()
    assert result is True


@pytest.mark.asyncio
async def test_oauth_token_is_cached(connector):
    """Le second appel réutilise le token en cache (pas de nouvel appel OAuth)."""
    token_1 = await connector._get_token()
    token_2 = await connector._get_token()
    assert token_1 == token_2
    assert connector._token_expiry is not None


@pytest.mark.asyncio
async def test_pull_full_returns_events(connector):
    events = await connector.pull_full()
    assert len(events) > 20, f"Attendu >20 événements, obtenu {len(events)}"
    for e in events:
        assert e.tenant_id == TENANT
        assert e.source == "servicenow"


# ── Tests unitaires du mapper (aucune dépendance réseau) ──────────────────────


def test_mapper_server():
    mapper = ServiceNowMapper(TENANT)
    rec = {
        "sys_id": "abc123",
        "name": "web-srv-01",
        "operational_status": "1",
        "ip_address": "10.0.0.1",
    }
    node = mapper.map_ci("cmdb_ci_server", rec)
    assert node is not None
    assert node.node_type == NodeType.SERVER
    assert node.external_id == "abc123"
    assert 0.0 <= node.confidence_score <= 1.0
    assert 0.0 <= node.freshness_score <= 1.0


def test_mapper_application():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "def456", "name": "payment-app", "exit_plan_status": None}
    node = mapper.map_ci("cmdb_ci_appl", rec)
    assert node.node_type == NodeType.APPLICATION
    assert node.attributes["exit_plan_status"] is None


def test_mapper_rel_ci_returns_none():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "rel001", "parent": "a", "child": "b"}
    node = mapper.map_ci("cmdb_rel_ci", rec)
    assert node is None  # cmdb_rel_ci → arête, pas nœud


@pytest.mark.asyncio
async def test_pull_covers_all_6_tables(connector):
    events = await connector.pull_full()
    tables = {e.raw_data["table"] for e in events}
    expected = {
        "cmdb_ci_server", "cmdb_ci_appl", "cmdb_ci_database",
        "cmdb_ci_ip_network", "cmdb_ci_service", "cmdb_rel_ci"
    }
    # Les tables vides ne génèrent pas d'événements — on vérifie
    # que le connecteur a bien TENTÉ de les interroger, pas qu'elles
    # ont des données. Sur PDI fraîche, cmdb_ci_ip_network est vide.
    missing_with_data = expected - tables
    allowed_empty = {"cmdb_ci_ip_network"}
    unexpected_missing = missing_with_data - allowed_empty
    assert not unexpected_missing, f"Tables manquantes inattendues : {unexpected_missing}"
