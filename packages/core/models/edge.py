# packages/core/models/edge.py
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

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
    sources: List[str] = []

    # Temporalité
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Attributs de la relation
    attributes: Dict[str, Any] = {}