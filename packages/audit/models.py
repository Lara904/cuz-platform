# packages/audit/models.py
"""Modèle de l'événement d'audit JIT/remédiation (P2.12). Même style que
services.api.audit.AuditEntry (P1) et services.api.er_audit (P2.6) : un dataclass
immuable (frozen) par table d'audit --- chaque table couvre un périmètre distinct
(ici : acquisition/révocation JIT et exécution de remédiation, RÈGLE 6/7), jamais
une table générique fourre-tout."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    tenant_id: str
    action_id: str
    event_type: str  # jit_credential_acquired | remediation_executed | jit_credential_revoked
    actor: str  # nom de classe de l'agent, ou id d'un reviewer humain
    payload: dict[str, Any] = field(default_factory=dict)
    finding_id: str | None = None
    created_at: datetime | None = None  # None --- laissé à DEFAULT now() en base
