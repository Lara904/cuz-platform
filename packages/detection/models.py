# packages/detection/models.py
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
FindingStatus = Literal["open", "acknowledged", "false_positive", "resolved"]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    affected_nodes: list[str]  # node.id
    affected_node_names: list[str]
    remediation_hint: str
    # Confiance = min des confidence_score des nœuds affectés (renseignée par le runner)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    status: FindingStatus = "open"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = {}
