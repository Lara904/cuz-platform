# packages/core/interfaces/mock_connector.py
"""Mock connecteur implémentant IConnector — utilisé uniquement pour les tests."""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from packages.core.interfaces.connector import IConnector
from packages.core.models.enums import NodeType
from packages.core.models.events import EventType, RawEvent


class MockConnector(IConnector):
    """Implémentation minimale de IConnector pour valider le contrat."""

    def __init__(self, tenant_id: str, config: dict[str, object], should_fail: bool = False):
        super().__init__(tenant_id, config)
        self.should_fail = should_fail
        self._pull_count = 0

    async def test_connection(self) -> bool:
        if self.should_fail:
            raise ConnectionError("Mock connection failure")
        return True

    async def pull_full(self) -> list[RawEvent]:
        self._pull_count += 1
        return [
            RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="mock",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(UTC),
                raw_data={"name": "mock-server-01", "type": NodeType.SERVER},
            ),
            RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="mock",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(UTC),
                raw_data={"name": "mock-app-01", "type": NodeType.APPLICATION},
            ),
        ]

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        for i in range(3):
            yield RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="mock",
                event_type=EventType.NODE_UPDATED,
                timestamp=datetime.now(UTC),
                raw_data={"name": f"mock-event-{i}"},
            )
