"""
services/api/models/connector.py
Schémas Pydantic pour les connecteurs par tenant.
"""
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ConnectorType(str, Enum):  # noqa: UP042 — str()/format() inchangés vs StrEnum
    SERVICENOW = "servicenow"
    AZURE = "azure"
    ENTRA_ID = "entra_id"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    DATADOG = "datadog"
    TERRAFORM = "terraform"
    MANUAL = "manual"


class ConnectorStatus(str, Enum):  # noqa: UP042 — str()/format() inchangés vs StrEnum
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    PENDING = "pending"


class ConnectorCreate(BaseModel):
    type: ConnectorType
    name: str = Field(..., min_length=2, max_length=128)
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration spécifique au connecteur (credentials, URLs, etc.)",
    )


class ConnectorUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=128)
    config: dict[str, Any] | None = None
    status: ConnectorStatus | None = None


class ConnectorResponse(BaseModel):
    id: str
    tenant_id: str
    type: ConnectorType
    name: str
    status: ConnectorStatus
    last_sync: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ConnectorTestResult(BaseModel):
    success: bool
    message: str
    latency_ms: float | None = None
