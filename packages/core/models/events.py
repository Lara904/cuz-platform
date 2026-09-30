# packages/core/models/events.py
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from packages.core.models.edge import CuzEdge
from packages.core.models.node import CuzNode


class EventType(StrEnum):
    NODE_CREATED = "NODE_CREATED"
    NODE_UPDATED = "NODE_UPDATED"
    NODE_DELETED = "NODE_DELETED"
    EDGE_CREATED = "EDGE_CREATED"
    EDGE_UPDATED = "EDGE_UPDATED"
    EDGE_DELETED = "EDGE_DELETED"


class RawEvent(BaseModel):
    """Produit par les connecteurs — format brut de la source."""

    event_id: str
    tenant_id: str
    source: str
    event_type: EventType
    timestamp: datetime
    raw_data: dict[str, Any]
    schema_version: str = "1.0"


class NormalizedEvent(BaseModel):
    """Produit après normalisation — prêt pour Neo4j."""

    event_id: str
    raw_event_id: str
    tenant_id: str
    source: str
    event_type: EventType
    timestamp: datetime
    node: CuzNode | None = None  # inchangé
    edge: CuzEdge | None = None  # NOUVEAU (V3)
    schema_version: str = "1.0"
