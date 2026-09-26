# packages/connectors/entra_id/mapper.py
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType
from packages.core.scoring import compute_confidence, compute_freshness

class EntraIDMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_user(self, rec: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.USER,
            name=rec.get("displayName", "unknown"),
            external_id=rec.get("id"),
            external_ids={"entra_id": rec.get("id", "")},
            confidence_score=compute_confidence(["entra_id"]),
            freshness_score=compute_freshness(NodeType.USER, last_seen),
            sources=["entra_id"],
            last_seen=last_seen,
            attributes={
                "upn":             rec.get("userPrincipalName"),
                "account_enabled": rec.get("accountEnabled"),
                "has_mfa":         rec.get("has_mfa", False),
                "mfa_methods":     [m.get("@odata.type")
                                    for m in rec.get("mfa_methods", [])],
                "created_at":      rec.get("createdDateTime"),
            },
            tags={"source": "entra_id", "object_type": "user"},
        )

    def map_service_principal(self, rec: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        creds = rec.get("passwordCredentials", [])
        expired = any(
            c.get("endDateTime") and
            c["endDateTime"] < datetime.now(timezone.utc).isoformat()
            for c in creds
        )
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.SERVICE_ACCOUNT,
            name=rec.get("displayName", "unknown"),
            external_id=rec.get("id"),
            external_ids={"entra_id": rec.get("id", "")},
            confidence_score=compute_confidence(["entra_id"]),
            freshness_score=compute_freshness(NodeType.SERVICE_ACCOUNT, last_seen),
            sources=["entra_id"],
            last_seen=last_seen,
            attributes={
                "app_id":          rec.get("appId"),
                "account_enabled": rec.get("accountEnabled"),
                "has_expired_creds": expired,
            },
            tags={"source": "entra_id", "object_type": "service_principal"},
        )