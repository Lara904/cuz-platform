# packages/connectors/cloud_detection/connector.py
"""Connecteur détection cloud (P2.2) : alertes et recommandations d'un bus de détection
(Defender for Cloud via Event Hub). En local, la source est le simulateur
tests/fixtures/defender_alerts_sim (fictif). Seuls l'URL et les credentials changent en réel.

RÈGLE 1 : aucune écriture dans Neo4j, tout passe par Redpanda.
"""
import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import EventType, RawEvent


class CloudDetectionConnector(IConnector):
    def __init__(self, tenant_id: str, eventhub_url: str, credentials: dict,
                 transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(tenant_id, credentials)
        self.eventhub_url = eventhub_url.rstrip("/")
        self.credentials = credentials
        self.transport = transport  # injectable pour les tests

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self.transport)

    async def test_connection(self) -> bool:
        async with self._client(15) as client:
            r = await client.get(f"{self.eventhub_url}/health")
            return r.status_code == 200

    async def pull_full(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        async with self._client(30) as client:
            r = await client.get(f"{self.eventhub_url}/alerts")
            r.raise_for_status()
            events += [self._wrap("alert", a) for a in r.json().get("alerts", [])]
            r2 = await client.get(f"{self.eventhub_url}/recommendations")
            r2.raise_for_status()
            events += [self._wrap("recommendation", rec)
                       for rec in r2.json().get("recommendations", [])]
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        cursor: str | None = None
        while True:
            async with self._client(30) as client:
                params = {"since": cursor} if cursor else {}
                r = await client.get(f"{self.eventhub_url}/alerts/stream", params=params)
                if r.status_code == 200:
                    payload = r.json()
                    cursor = payload.get("cursor", cursor)
                    for alert in payload.get("alerts", []):
                        yield self._wrap("alert", alert)
            await asyncio.sleep(120)  # poll toutes les 2 min (P2.7 réduira ça)

    def _wrap(self, object_type: str, data: dict) -> RawEvent:
        return RawEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            source="cloud_detection",
            event_type=EventType.NODE_CREATED,
            timestamp=datetime.now(UTC),
            raw_data={"object_type": object_type, "record": data},
        )
