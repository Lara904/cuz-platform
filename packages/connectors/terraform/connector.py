# packages/connectors/terraform/connector.py
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

from packages.connectors.terraform.mapper import load_resources
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import EventType, RawEvent

DEFAULT_TFSTATE = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "acmecorp.tfstate"


class TerraformConnector(IConnector):
    """Source IaC statique (fichier tfstate) — Phase 1, pas de temps réel."""

    @property
    def path(self) -> Path:
        return Path(self.config.get("path", DEFAULT_TFSTATE))  # type: ignore[arg-type]

    async def test_connection(self) -> bool:
        if not self.path.is_file():
            raise FileNotFoundError(f"tfstate introuvable : {self.path}")
        return True

    async def pull_full(self) -> list[RawEvent]:
        now = datetime.now(UTC)
        return [
            RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="terraform",
                event_type=EventType.NODE_CREATED,
                timestamp=now,
                raw_data={"object_type": "resource", "resource": resource},
            )
            for resource in load_resources(self.path)
        ]

    def subscribe_events(self) -> AsyncIterator[RawEvent]:
        raise NotImplementedError("tfstate : source statique, pas de flux temps réel")
