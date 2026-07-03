# packages/core/models/node.py
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from packages.core.models.enums import NodeType


class CuzNode(BaseModel):
    # Identité
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    node_type: NodeType
    name: str

    # Identifiants externes (CMDB, ARM, GitHub, etc.)
    external_id: Optional[str] = None
    external_ids: Dict[str, str] = {}

    # Qualité de la donnée — OBLIGATOIRES
    confidence_score: float = Field(ge=0.0, le=1.0)
    freshness_score: float = Field(ge=0.0, le=1.0)
    sources: List[str] = []

    # Temporalité
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Données métier
    attributes: Dict[str, Any] = {}
    tags: Dict[str, str] = {}

    @field_validator('confidence_score', 'freshness_score')
    @classmethod
    def validate_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f'Score must be between 0.0 and 1.0, got {v}')
        return round(v, 4)