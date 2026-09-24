# packages/connectors/minio/mapper.py
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType
from packages.core.scoring import compute_confidence, compute_freshness

class MinIOMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_bucket(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        contains_pii = any(
            obj.get("tags", {}).get("contains_pii") == "true"
            for obj in raw.get("objects", [])
        )
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.STORAGE,
            name=raw["bucket_name"],
            external_id=raw["bucket_name"],
            external_ids={"minio": raw["bucket_name"]},
            confidence_score=compute_confidence(["minio"]),
            freshness_score=compute_freshness(NodeType.STORAGE, last_seen),
            sources=["minio"],
            last_seen=last_seen,
            attributes={
                "is_public":    raw.get("is_public", False),
                "contains_pii": contains_pii,
                "object_count": len(raw.get("objects", [])),
                "endpoint":     raw.get("endpoint"),
                "creation_date": raw.get("creation_date"),
            },
            tags={
                **raw.get("tags", {}),
                "source": "minio",
            },
        )