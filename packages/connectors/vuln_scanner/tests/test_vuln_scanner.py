# packages/connectors/vuln_scanner/tests/test_vuln_scanner.py
import json
from datetime import UTC, datetime

import httpx
import pytest

from packages.connectors.vuln_scanner.connector import VulnScannerConnector
from packages.connectors.vuln_scanner.correlate import GraphNode, correlate, version_matches
from packages.connectors.vuln_scanner.epss_client import EPSSClient
from packages.connectors.vuln_scanner.mapper import VulnScannerMapper
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.events import EventType, RawEvent
from packages.core.models.node import CuzNode
from packages.ingestion.normalizer import Normalizer

TENANT = "acmecorp"
FIXTURES = "tests/fixtures/acmecorp_cves.json"


def _epss_transport(known: dict[str, tuple[float, float]]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        cve = request.url.params["cve"]
        if cve not in known:
            return httpx.Response(200, json={"data": []})
        score, pct = known[cve]
        return httpx.Response(
            200, json={"data": [{"cve": cve, "epss": str(score), "percentile": str(pct)}]}
        )

    return httpx.MockTransport(handler)


def _connector(transport: httpx.AsyncBaseTransport) -> VulnScannerConnector:
    return VulnScannerConnector(
        TENANT, fixtures_path=FIXTURES, epss_client=EPSSClient(transport=transport)
    )


@pytest.mark.asyncio
async def test_test_connection_ok_and_ko(tmp_path):
    assert await _connector(_epss_transport({})).test_connection() is True
    ko = VulnScannerConnector(TENANT, fixtures_path=str(tmp_path / "absent.json"))
    assert await ko.test_connection() is False


@pytest.mark.asyncio
async def test_pull_full_enriches_epss_from_api():
    events = await _connector(_epss_transport({"CVE-2022-24999": (0.94, 0.99)})).pull_full()
    rec = {e.raw_data["record"]["cve_id"]: e.raw_data["record"] for e in events}
    assert rec["CVE-2022-24999"]["cvss_score"] == 9.8
    assert rec["CVE-2022-24999"]["epss_score"] == 0.94
    assert rec["CVE-2022-24999"]["epss_source"] == "first.org"
    # CVE inconnue de l'API : repli sur la valeur du scanner, origine tracée
    assert rec["CVE-2021-23337"]["epss_score"] == 0.42
    assert rec["CVE-2021-23337"]["epss_source"] == "scanner"


@pytest.mark.asyncio
async def test_pull_full_api_down_falls_back():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("réseau coupé")

    events = await _connector(httpx.MockTransport(boom)).pull_full()
    qs = next(e for e in events if e.raw_data["record"]["cve_id"] == "CVE-2022-24999")
    assert qs.raw_data["record"]["epss_score"] == 0.78
    assert qs.raw_data["record"]["epss_source"] == "scanner"


def test_mapper_cve_node():
    node = VulnScannerMapper(TENANT).map_cve(
        {
            "cve_id": "CVE-2022-24999",
            "cvss_score": 9.8,
            "epss_score": 0.94,
            "package": "qs",
            "version_affected": "<6.7.3",
            "patch_status": "not_patched",
        }
    )
    assert node.node_type == NodeType.VULNERABILITY
    assert node.attributes["cvss_score"] == 9.8
    assert node.attributes["epss_score"] == 0.94
    assert node.attributes["patch_status"] == "not_patched"
    assert node.confidence_score >= 0.7  # sous 0.7 : quarantaine
    assert node.freshness_score == 1.0


def test_mapper_affects_edge():
    mapper = VulnScannerMapper(TENANT)
    now = datetime.now(UTC)
    cve = CuzNode(
        tenant_id=TENANT,
        node_type=NodeType.VULNERABILITY,
        name="CVE-2022-24999",
        confidence_score=0.85,
        freshness_score=1.0,
        sources=["vuln_scanner"],
        last_seen=now,
    )
    dep = CuzNode(
        tenant_id=TENANT,
        node_type=NodeType.VULNERABILITY,
        name="qs@6.5.2",
        confidence_score=0.88,
        freshness_score=1.0,
        sources=["gitea"],
        last_seen=now,
    )
    edge = mapper.map_affects_edge(cve, dep)
    assert edge.edge_type == EdgeType.AFFECTS
    assert edge.confidence_score is not None and edge.freshness_score is not None
    assert edge.confidence_score >= 0.7


def test_normalizer_cve_event_has_stable_id():
    raw = RawEvent(
        event_id="e1",
        tenant_id=TENANT,
        source="vuln_scanner",
        event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(UTC),
        raw_data={
            "object_type": "cve_finding",
            "record": {"cve_id": "CVE-2022-24999", "cvss_score": 9.8},
        },
    )
    (event,) = Normalizer().normalize(raw)
    assert event.node is not None and event.node.id == "vuln_scanner:CVE-2022-24999"


@pytest.mark.parametrize(
    "version,constraint,expected",
    [
        ("6.5.2", "<6.7.3", True),
        ("6.7.3", "<6.7.3", False),
        ("4.17.21", "<4.17.21", False),
        ("1.5", ">=1.0,<2.0", True),
        ("2.0", ">=1.0,<2.0", False),
        ("6.5.2", None, False),
        ("pas-une-version", "<6.7.3", False),
    ],
)
def test_version_matches(version, constraint, expected):
    assert version_matches(version, constraint) is expected


def test_correlate_links_cve_to_matching_dependency_only():
    cves = [
        GraphNode(
            "vuln_scanner:CVE-2022-24999",
            "CVE-2022-24999",
            {"package": "qs", "version_affected": "<6.7.3"},
            ("vuln_scanner",),
        )
    ]
    deps = [
        GraphNode(
            "gitea:qs@6.5.2", "qs@6.5.2", {"package_name": "qs", "version": "6.5.2"}, ("gitea",)
        ),
        GraphNode(
            "gitea:qs@6.10.3", "qs@6.10.3", {"package_name": "qs", "version": "6.10.3"}, ("gitea",)
        ),
        GraphNode(
            "gitea:lodash@4.17.21",
            "lodash@4.17.21",
            {"package_name": "lodash", "version": "4.17.21"},
            ("gitea",),
        ),
    ]
    edges = correlate(cves, deps, TENANT)
    assert [(e.source_id, e.target_id) for e in edges] == [
        ("vuln_scanner:CVE-2022-24999", "gitea:qs@6.5.2")
    ]
    assert edges[0].edge_type == EdgeType.AFFECTS
    assert edges[0].confidence_score >= 0.7


def test_fixture_is_valid_json_list():
    with open(FIXTURES, encoding="utf-8") as f:
        assert any(c["cve_id"] == "CVE-2022-24999" for c in json.load(f))
