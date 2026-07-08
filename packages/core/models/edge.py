# packages/core/models/edge.py
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from packages.core.models.enums import EdgeType


class CuzEdge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    edge_type: EdgeType
    source_id: str
    target_id: str

    # Qualité — OBLIGATOIRES
    confidence_score: float = Field(ge=0.0, le=1.0)
    freshness_score: float = Field(ge=0.0, le=1.0)
    sources: list[str] = []

    # Temporalité
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Attributs de la relation
    attributes: dict[str, Any] = {}
