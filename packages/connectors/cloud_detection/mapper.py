# packages/connectors/cloud_detection/mapper.py
from datetime import UTC, datetime
from typing import Any, Protocol

from packages.core.models.enums import NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness


class _HasAttributes(Protocol):
    @property
    def attributes(self) -> dict[str, Any]: ...


def _node(
    tenant_id: str, rec: dict[str, Any], name: str, subtype: str, attributes: dict[str, Any]
) -> CuzNode:
    last_seen = datetime.now(UTC)
    return CuzNode(
        tenant_id=tenant_id,
        node_type=NodeType.VULNERABILITY,  # pas de NodeType ALERT : voir docstring map_alert
        name=name,
        external_id=rec.get("id"),
        external_ids={"cloud_detection": rec.get("id", "")},
        confidence_score=compute_confidence(["cloud_detection"]),
        freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
        sources=["cloud_detection"],
        last_seen=last_seen,
        attributes=attributes,
        tags={"source": "cloud_detection", "node_subtype": subtype},
    )


class CloudDetectionMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_alert(self, rec: dict[str, Any]) -> CuzNode:
        """Une alerte cloud est un VULNERABILITY avec node_subtype='cloud_alert' (tag natif
        filtrable). Ajouter un NodeType ALERT ne se justifie qu'au volume d'un futur client."""
        return _node(
            self.tenant_id,
            rec,
            rec.get("alert_name", rec.get("id", "unknown")),
            "cloud_alert",
            {
                "severity": rec.get("severity"),
                "rule_id": rec.get("rule_id"),
                "resource_id": rec.get("resource_id"),
                "status": rec.get("status"),
                "description": rec.get("description"),
            },
        )

    def map_recommendation(self, rec: dict[str, Any]) -> CuzNode:
        return _node(
            self.tenant_id,
            rec,
            rec.get("recommendation_name", rec.get("id", "unknown")),
            "recommendation",
            {
                "rule_id": rec.get("rule_id"),
                "resource_id": rec.get("resource_id"),
                "remediation_hint": rec.get("remediation"),
            },
        )


def deduplicate_against_cypher_findings[T: _HasAttributes](
    cloud_nodes: list[T], cypher_rule_ids: set[str]
) -> list[T]:
    """Retire les nœuds cloud dont le rule_id est déjà couvert par un finding Cypher :
    un IAM-001 vu par Defender ET par le moteur ne remonte pas deux fois."""
    return [n for n in cloud_nodes if n.attributes.get("rule_id") not in cypher_rule_ids]
