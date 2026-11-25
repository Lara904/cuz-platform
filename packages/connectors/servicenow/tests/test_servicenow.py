# packages/connectors/servicenow/tests/test_servicenow.py
import functools
import os

import httpx
import pytest

from packages.connectors.servicenow.connector import ServiceNowConnector
from packages.connectors.servicenow.mapper import ServiceNowMapper
from packages.core.models.enums import EdgeType, NodeType

TENANT = "acmecorp"
INSTANCE = "https://dev353984.service-now.com"


def skip_if_instance_5xx(test):
    """Tests live : skip UNIQUEMENT si le PDI renvoie une erreur 5xx (instance indisponible).
    Toute autre erreur reste un échec."""

    @functools.wraps(test)
    async def wrapper(*args, **kwargs):
        try:
            return await test(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 500:
                pytest.skip(f"instance ServiceNow indisponible ({e.response.status_code})")
            raise

    return wrapper


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


@pytest.mark.live_integration("servicenow")
@pytest.mark.asyncio
@skip_if_instance_5xx
async def test_connection_returns_true(connector):
    """test_connection() doit retourner True sur le PDI réel via OAuth."""
    result = await connector.test_connection()
    assert result is True


@pytest.mark.live_integration("servicenow")
@pytest.mark.asyncio
@skip_if_instance_5xx
async def test_oauth_token_is_cached(connector):
    """Le second appel réutilise le token en cache (pas de nouvel appel OAuth)."""
    token_1 = await connector._get_token()
    token_2 = await connector._get_token()
    assert token_1 == token_2
    assert connector._token_expiry is not None


@pytest.mark.live_integration("servicenow")
@pytest.mark.asyncio
@skip_if_instance_5xx
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


# ── map_relationship (P2.13bis, FIX-1/P1.16) ──────────────────────────────────


def test_map_relationship_builds_depends_on_edge():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "rel001", "parent": "tp001", "child": "app001", "type": "somehash"}
    edge = mapper.map_relationship(rec)
    assert edge is not None
    assert edge.edge_type == EdgeType.DEPENDS_ON
    assert edge.source_id == "servicenow:tp001"
    assert edge.target_id == "servicenow:app001"
    assert edge.tenant_id == TENANT
    assert edge.attributes["cmdb_rel_type_sys_id"] == "somehash"


def test_map_relationship_returns_none_without_parent():
    mapper = ServiceNowMapper(TENANT)
    assert mapper.map_relationship({"sys_id": "rel002", "child": "app001"}) is None


def test_map_relationship_returns_none_without_child():
    mapper = ServiceNowMapper(TENANT)
    assert mapper.map_relationship({"sys_id": "rel003", "parent": "tp001"}) is None


def test_mapper_third_party_vendor():
    mapper = ServiceNowMapper(TENANT)
    rec = {
        "sys_id": "tp001",
        "name": "Acme-Payment-SaaS",
        "u_vendor_type": "third_party",
        "exit_plan_status": None,
    }
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.THIRD_PARTY


def test_mapper_appl_third_party_vendor():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "tp002", "name": "Vendor-App", "u_vendor_type": "third_party"}
    node = mapper.map_ci("cmdb_ci_appl", rec)
    assert node.node_type == NodeType.THIRD_PARTY


def test_mapper_service_without_vendor_type_stays_application():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc001", "name": "internal-billing"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.APPLICATION


# ── business_criticality -> BUSINESS_FUNCTION (P2.13bis / DEC-011) ──────────────────


def test_mapper_critical_service_becomes_business_function():
    """business_criticality='1' (OOB ServiceNow : "1 - most critical") sur un
    cmdb_ci_service interne doit promouvoir le nœud en BUSINESS_FUNCTION, avec
    criticality_raw='critical' promu dans attributes pour être filtrable par
    DORA-CONCENTRATION-001 (packages/graph/writer.py, NATIVE_PROMOTED_KEYS)."""
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc002", "name": "SAP Payroll", "business_criticality": "1"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.BUSINESS_FUNCTION
    assert node.attributes["criticality_raw"] == "critical"


def test_mapper_somewhat_critical_service_becomes_business_function():
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc003", "name": "CRM interne", "business_criticality": "2"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.BUSINESS_FUNCTION
    assert node.attributes["criticality_raw"] == "high"


def test_mapper_low_criticality_service_stays_application():
    """criticality_raw='low' est bien calculé et conservé (traçabilité), mais ne
    déclenche pas de promotion en BUSINESS_FUNCTION -- seul 'critical'/'high' le fait,
    même vocabulaire que la règle Cypher DORA-CONCENTRATION-001."""
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc004", "name": "Outil interne mineur", "business_criticality": "4"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.APPLICATION
    assert node.attributes["criticality_raw"] == "low"


def test_mapper_missing_business_criticality_stays_application():
    """Valeur absente (le cas réel observé sur le PDI démo de Lara, non peuplé) : aucune
    criticité devinée, le CI reste APPLICATION comme avant ce changement."""
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc005", "name": "internal-billing"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.APPLICATION
    assert node.attributes["criticality_raw"] is None


def test_mapper_busines_criticality_typo_field_name_also_works():
    """Confirmé par dump brut des champs sur le PDI réel de Lara (dev421064) : le champ
    s'appelle `busines_criticality` (une seule "s") sur cette instance, pas
    `business_criticality` -- coquille réelle de la donnée de démo ServiceNow, pas de
    notre côté. On doit la reconnaître sans que ce soit documenté ailleurs que par ce
    test et le commentaire du code."""
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc006", "name": "SAP Payroll", "busines_criticality": "1"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.BUSINESS_FUNCTION
    assert node.attributes["criticality_raw"] == "critical"


def test_mapper_criticality_as_full_label_not_raw_code():
    """Toujours confirmé sur le PDI réel : avec sysparm_display_value=false (déjà le
    réglage de connector.py), ce champ ne renvoie pas le code brut "1" mais le libellé
    entier "1 - most critical" -- value et display_value identiques dans le dump. Seul
    le premier caractère est significatif, pas le texte complet du libellé."""
    mapper = ServiceNowMapper(TENANT)
    rec = {"sys_id": "svc007", "name": "SAP Payroll", "busines_criticality": "1 - most critical"}
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.BUSINESS_FUNCTION
    assert node.attributes["criticality_raw"] == "critical"


def test_mapper_third_party_vendor_ignores_business_criticality():
    """Un prestataire tiers (u_vendor_type=third_party) reste THIRD_PARTY même si
    business_criticality est renseigné -- c'est un prestataire, pas la fonction métier
    qu'il supporte."""
    mapper = ServiceNowMapper(TENANT)
    rec = {
        "sys_id": "tp003",
        "name": "Acme-Payment-SaaS",
        "u_vendor_type": "third_party",
        "business_criticality": "1",
    }
    node = mapper.map_ci("cmdb_ci_service", rec)
    assert node.node_type == NodeType.THIRD_PARTY


@pytest.mark.live_integration("servicenow")
@pytest.mark.asyncio
@skip_if_instance_5xx
async def test_pull_covers_all_6_tables(connector):
    events = await connector.pull_full()
    tables = {e.raw_data["table"] for e in events}
    expected = {
        "cmdb_ci_server",
        "cmdb_ci_appl",
        "cmdb_ci_database",
        "cmdb_ci_ip_network",
        "cmdb_ci_service",
        "cmdb_rel_ci",
    }
    # Les tables vides ne génèrent pas d'événements — on vérifie
    # que le connecteur a bien TENTÉ de les interroger, pas qu'elles
    # ont des données. Sur PDI fraîche, cmdb_ci_ip_network est vide.
    missing_with_data = expected - tables
    allowed_empty = {"cmdb_ci_ip_network"}
    unexpected_missing = missing_with_data - allowed_empty
    assert not unexpected_missing, f"Tables manquantes inattendues : {unexpected_missing}"
