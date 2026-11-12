# packages/connectors/vuln_scanner/connector.py
"""Connecteur scanner de vulnérabilités (P2.4) : CVE + enrichissement EPSS (FIRST.org).
En local, la source est tests/fixtures/acmecorp_cves.json (liste de CVE) ; seuls l'URL et
la clé API changent avec un scanner réel (Defender Vulnerability Management ou équivalent).

RÈGLE 1 : aucune écriture dans Neo4j, tout passe par Redpanda.
"""

import asyncio
import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

import httpx

from packages.connectors.vuln_scanner.epss_client import EPSSClient
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import EventType, RawEvent


class VulnScannerConnector(IConnector):
    def __init__(
        self,
        tenant_id: str,
        scanner_url: str = "",
        api_key: str = "",
        fixtures_path: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        epss_client: EPSSClient | None = None,
    ):
        super().__init__(tenant_id, {"scanner_url": scanner_url})
        self.scanner_url = scanner_url.rstrip("/")
        self.api_key = api_key
        self.fixtures_path = fixtures_path
        self.transport = transport
        self.epss_client = epss_client or EPSSClient()

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout,
            transport=self.transport,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

    async def test_connection(self) -> bool:
        if self.fixtures_path:
            return os.path.exists(self.fixtures_path)
        async with self._client(15) as client:
            r = await client.get(f"{self.scanner_url}/health")
            return r.status_code == 200

    async def _load_cves(self) -> list[dict[str, Any]]:
        if self.fixtures_path:
            with open(self.fixtures_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else data.get("cves", [])
        async with self._client(30) as client:
            r = await client.get(f"{self.scanner_url}/findings")
            r.raise_for_status()
            return cast(list[dict[str, Any]], r.json().get("findings", []))

    async def pull_full(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        for cve in await self._load_cves():
            record = dict(cve)
            epss = await self.epss_client.get_epss(record["cve_id"])
            if epss:
                record.update(epss, epss_source="first.org")
            elif record.get("epss_score") is not None:
                record["epss_source"] = "scanner"  # repli : valeur fournie par le scanner
            events.append(self._wrap(record))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        while True:
            for event in await self.pull_full():
                yield event
            await asyncio.sleep(21600)  # poll 6h, aligné sur Entra ID

    def _wrap(self, record: dict[str, Any]) -> RawEvent:
        return RawEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            source="vuln_scanner",
            event_type=EventType.NODE_UPDATED,
            timestamp=datetime.now(UTC),
            raw_data={"object_type": "cve_finding", "record": record},
        )
