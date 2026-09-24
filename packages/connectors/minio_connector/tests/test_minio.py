# packages/connectors/minio/tests/test_minio.py
import pytest
import os
from packages.connectors.minio_connector.connector import MinIOConnector
from packages.connectors.minio_connector.mapper import MinIOMapper
from packages.core.models.enums import NodeType

@pytest.fixture
def connector():
    return MinIOConnector(
        tenant_id="acmecorp",
        endpoint=os.getenv("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.getenv("MINIO_USER", "acmeadmin"),
        secret_key=os.getenv("MINIO_PASSWORD", ""),
        secure=False,
    )

@pytest.mark.asyncio
async def test_connection(connector):
    assert await connector.test_connection() is True

@pytest.mark.asyncio
async def test_pull_full_returns_3_buckets(connector):
    events = await connector.pull_full()
    bucket_names = {e.raw_data["bucket_name"] for e in events}
    assert "acmecorp-data"   in bucket_names
    assert "acmecorp-logs"   in bucket_names
    assert "acmecorp-public" in bucket_names

@pytest.mark.asyncio
async def test_acmecorp_public_is_flagged(connector):
    events = await connector.pull_full()
    pub = next(e for e in events if e.raw_data["bucket_name"] == "acmecorp-public")
    assert pub.raw_data["is_public"] is True

@pytest.mark.asyncio
async def test_clients_pii_csv_detected(connector):
    events = await connector.pull_full()
    pub = next(e for e in events if e.raw_data["bucket_name"] == "acmecorp-public")
    pii_objs = [o for o in pub.raw_data["objects"]
                if o.get("tags", {}).get("contains_pii") == "true"]
    assert len(pii_objs) > 0

def test_mapper_bucket_node_type():
    mapper = MinIOMapper("acmecorp")
    raw = {"bucket_name": "acmecorp-public", "is_public": True,
           "objects": [{"name": "clients_pii.csv", "tags": {"contains_pii": "true"}}],
           "tags": {}, "endpoint": "localhost:9000"}
    node = mapper.map_bucket(raw)
    assert node.node_type == NodeType.STORAGE
    assert node.attributes["is_public"] is True
    assert node.attributes["contains_pii"] is True
    assert 0.0 <= node.confidence_score <= 1.0