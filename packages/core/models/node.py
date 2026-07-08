# packages/core/models/node.py
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from packages.core.models.enums import NodeType


class CuzNode(BaseModel):
    # Identité
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    node_type: NodeType
    name: str

    # Identifiants externes (CMDB, ARM, GitHub, etc.)
    external_id: str | None = None
    external_ids: dict[str, str] = {}

    # Qualité de la donnée — OBLIGATOIRES
    confidence_score: float = Field(ge=0.0, le=1.0)
    freshness_score: float = Field(ge=0.0, le=1.0)
    sources: list[str] = []

    # Temporalité
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Données métier
    attributes: dict[str, Any] = {}
    tags: dict[str, str] = {}

    @field_validator("confidence_score", "freshness_score")
    @classmethod
    def validate_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {v}")
        return round(v, 4)
