# packages/connectors/cloud_detection/tests/test_cloud_detection.py
import asyncio
import json
import os
from datetime import UTC, datetime

import httpx
import pytest

from packages.connectors.cloud_detection.connector import CloudDetectionConnector
from packages.connectors.cloud_detection.mapper import (
    CloudDetectionMapper,
    deduplicate_against_cypher_findings,
)
from packages.core.models.enums import NodeType
from packages.core.models.events import EventType, RawEvent
from packages.ingestion.normalizer import Normalizer

TENANT = "acmecorp"
SIM_URL = os.getenv("CLOUD_DETECTION_SIM_URL", "http://localhost:9100")


def test_mapper_alert():
    mapper = CloudDetectionMapper(TENANT)
    rec = {"id": "alert-001", "alert_name": "Port SSH exposé", "severity": "HIGH",
           "rule_id": "NET-001", "resource_id": "vm-prod-01", "status": "active"}
    node = mapper.map_alert(rec)
    assert node.node_type == NodeType.VULNERABILITY
    assert node.attributes["severity"] == "HIGH"
    assert node.tags["node_subtype"] == "cloud_alert"
    assert node.confidence_score >= 0.7  # sous 0.7 : quarantaine


def test_mapper_recommendation_subtype():
    node = CloudDetectionMapper(TENANT).map_recommendation({"id": "r1", "rule_id": "IAM-001"})
    assert node.tags["node_subtype"] == "recommendation"


def test_deduplicate_removes_known_rule_ids():
    mapper = CloudDetectionMapper(TENANT)
    nodes = [
        mapper.map_alert({"id": "a1", "rule_id": "NET-001"}),
        mapper.map_alert({"id": "a2", "rule_id": "NEW-CLOUD-001"}),
    ]
    deduped = deduplicate_against_cypher_findings(nodes, cypher_rule_ids={"NET-001"})
    assert len(deduped) == 1
    assert deduped[0].attributes["rule_id"] == "NEW-CLOUD-001"


def _sim_transport() -> httpx.MockTransport:
    alerts = [{"id": "a1", "alert_name": "x", "rule_id": "IAM-001", "severity": "HIGH"},
              {"id": "a2", "alert_name": "y", "rule_id": "STORAGE-PUBLIC-001", "severity": "HIGH"}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/alerts":
            return httpx.Response(200, json={"alerts": alerts})
        if request.url.path == "/recommendations":
            return httpx.Response(200, json={"recommendations": [{"id": "r1", "rule_id": "IAM-001"}]})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_pull_full_emits_alerts_and_recommendations():
    conn = CloudDetectionConnector(TENANT, "http://sim", {}, transport=_sim_transport())
    events = asyncio.run(conn.pull_full())
    assert [e.raw_data["object_type"] for e in events] == ["alert", "alert", "recommendation"]
    assert all(e.source == "cloud_detection" for e in events)


def test_test_connection_uses_health_endpoint():
    conn = CloudDetectionConnector(TENANT, "http://sim", {}, transport=_sim_transport())
    assert asyncio.run(conn.test_connection()) is True


def test_normalizer_yields_vulnerability_node_with_stable_id():
    raw = RawEvent(event_id="e1", tenant_id=TENANT, source="cloud_detection",
                   event_type=EventType.NODE_CREATED, timestamp=datetime.now(UTC),
                   raw_data={"object_type": "alert", "record": {"id": "a1", "alert_name": "x"}})
    results = Normalizer().normalize(raw)
    assert len(results) == 1
    assert results[0].node.node_type == NodeType.VULNERABILITY
    assert results[0].node.id == "cloud_detection:a1"
    json.loads(results[0].model_dump_json())  # sérialisable pour Redpanda


def test_live_simulator_serves_alerts():
    async def probe():
        async with httpx.AsyncClient(timeout=5) as client:
            return (await client.get(f"{SIM_URL}/health")).status_code
    try:
        status = asyncio.run(probe())
    except httpx.HTTPError:
        pytest.skip("simulateur Defender injoignable (docker compose up defender-sim)")
    assert status == 200
    conn = CloudDetectionConnector(TENANT, SIM_URL, {})
    events = asyncio.run(conn.pull_full())
    assert any(e.raw_data["record"].get("rule_id") == "IAM-001" for e in events)
