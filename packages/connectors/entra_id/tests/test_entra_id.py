# packages/connectors/entra_id/tests/test_entra_id.py
import pytest
import os
from packages.connectors.entra_id.connector import EntraIDConnector
from packages.connectors.entra_id.mapper import EntraIDMapper
from packages.core.models.enums import NodeType

@pytest.fixture
def connector():
    return EntraIDConnector(
        tenant_id_cuz="acmecorp",
        entra_tenant_id=os.getenv("ENTRA_TENANT_ID"),
        client_id=os.getenv("ENTRA_CLIENT_ID"),
        client_secret=os.getenv("ENTRA_CLIENT_SECRET"),
    )

@pytest.mark.asyncio
async def test_connection(connector):
    assert await connector.test_connection() is True

@pytest.mark.asyncio
async def test_pull_full_returns_users(connector):
    events = await connector.pull_full()
    users = [e for e in events if e.raw_data.get("object_type") == "user"]
    assert len(users) >= 6, f"Attendu >=6 users, obtenu {len(users)}"

@pytest.mark.asyncio
async def test_djana_dev_no_mfa(connector):
    events = await connector.pull_full()
    users = [e for e in events if e.raw_data.get("object_type") == "user"]
    djana = next(
        (e for e in users
         if "djana" in e.raw_data["record"].get("userPrincipalName","").lower()),
        None
    )
    assert djana is not None, "djana.dev non trouvée"
    assert djana.raw_data["record"]["has_mfa"] is False

@pytest.mark.asyncio
async def test_svc_pipeline_no_mfa(connector):
    events = await connector.pull_full()
    users = [e for e in events if e.raw_data.get("object_type") == "user"]
    svc = next(
        (e for e in users
         if "svc-pipeline" in e.raw_data["record"].get("userPrincipalName","").lower()),
        None
    )
    assert svc is not None, "svc-pipeline non trouvé"
    assert svc.raw_data["record"]["has_mfa"] is False

def test_mapper_user_has_mfa_false():
    mapper = EntraIDMapper("acmecorp")
    rec = {"id": "uid1", "displayName": "Djana Dev",
           "userPrincipalName": "djana.dev@acmecorp.onmicrosoft.com",
           "accountEnabled": True, "has_mfa": False,
           "mfa_methods": [], "createdDateTime": "2024-01-01T00:00:00Z"}
    node = mapper.map_user(rec)
    assert node.node_type == NodeType.USER
    assert node.attributes["has_mfa"] is False
    assert node.attributes["upn"] == "djana.dev@acmecorp.onmicrosoft.com"