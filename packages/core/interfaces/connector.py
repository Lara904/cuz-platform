from abc import ABC, abstractmethod
from typing import AsyncIterator, List

from packages.core.models.events import RawEvent
from abc import ABC, abstractmethod
from typing import AsyncIterator, List
from packages.core.models.events import RawEvent

class IConnector(ABC):
    """Interface obligatoire pour tous les connecteurs CUz.
    Un connecteur = un sous-dossier dans packages/connectors/.
    Jamais d'accès direct à Neo4j depuis un connecteur."""

    def __init__(self, tenant_id: str, config: dict):
        self.tenant_id = tenant_id
        self.config = config

    @abstractmethod
    async def test_connection(self) -> bool:
        """Vérifie que la source est accessible. Lève une exception si non."""
        ...

    @abstractmethod
    async def pull_full(self) -> List[RawEvent]:
        """Scan complet de la source. Retourne tous les RawEvents.
        Idempotent : même appel = mêmes events (ne pas modifier l'état).
        """
        ...

    @abstractmethod
    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Souscription aux événements temps réel (webhooks, watch, etc.).
        Yield des RawEvents au fur et à mesure de leur réception.
        """
        ...