"""
services/api/models/tenant.py
Schémas Pydantic pour la gestion des tenants.
"""
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class TenantStatus(str, Enum):  # noqa: UP042 — str()/format() inchangés vs StrEnum
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"


class TenantCreate(BaseModel):
    id: str = Field(
        ...,
        pattern=r"^[a-z0-9\-]+$",
        min_length=3,
        max_length=64,
        description="Identifiant unique du tenant (slug, ex: stellantis-financial)",
        examples=["stellantis-financial"],
    )
    name: str = Field(..., min_length=2, max_length=128, description="Nom lisible du tenant")
    description: str | None = Field(None, max_length=512)


class TenantUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=128)
    description: str | None = Field(None, max_length=512)
    status: TenantStatus | None = None


class TenantResponse(BaseModel):
    id: str
    name: str
    description: str | None
    status: TenantStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
