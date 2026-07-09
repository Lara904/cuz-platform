"""
services/api/models/connector.py
Schémas Pydantic pour les connecteurs par tenant.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ConnectorType(str, Enum):
    SERVICENOW = "servicenow"
    AZURE = "azure"
    ENTRA_ID = "entra_id"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    DATADOG = "datadog"
    TERRAFORM = "terraform"
    MANUAL = "manual"


class ConnectorStatus(str, Enum):
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    PENDING = "pending"


class ConnectorCreate(BaseModel):
    type: ConnectorType
    name: str = Field(..., min_length=2, max_length=128)
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration spécifique au connecteur (credentials, URLs, etc.)",
    )


class ConnectorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    config: Optional[Dict[str, Any]] = None
    status: Optional[ConnectorStatus] = None


class ConnectorResponse(BaseModel):
    id: str
    tenant_id: str
    type: ConnectorType
    name: str
    status: ConnectorStatus
    last_sync: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ConnectorTestResult(BaseModel):
    success: bool
    message: str
    latency_ms: Optional[float] = None