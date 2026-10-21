# packages/connectors/terraform/mapper.py
import json
from datetime import UTC, datetime
from pathlib import Path

from packages.core.models.enums import NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness

# Types de ressources Terraform reconnus → type de nœud CUz.
# Les autres types sont ignorés (pas d'invention de mapping).
RESOURCE_TYPE_TO_NODE_TYPE = {
    "minio_bucket": NodeType.STORAGE,
    "kubernetes_deployment": NodeType.CONTAINER,
}


class TerraformMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_resource(self, resource: dict) -> CuzNode | None:
        node_type = RESOURCE_TYPE_TO_NODE_TYPE.get(resource["type"])
        if node_type is None:
            return None
        attrs = resource.get("attributes", {})
        # Le nom réel de la ressource : bucket pour minio, sinon nom Terraform
        name = attrs.get("bucket") or resource["name"]
        last_seen = datetime.now(UTC)
        external_id = f"{resource['type']}.{resource['name']}"
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=node_type,
            name=name,
            external_id=external_id,
            external_ids={"terraform": external_id},
            confidence_score=compute_confidence(["terraform"]),
            freshness_score=compute_freshness(node_type, last_seen),
            sources=["terraform"],
            last_seen=last_seen,
            attributes={"tf_type": resource["type"], "namespace": attrs.get("namespace")},
            tags={"source": "terraform", "iac_managed": "true", "tf_type": resource["type"]},
        )


def load_resources(path: Path) -> list[dict]:
    """Lit un fichier tfstate (version 4) et retourne les ressources aplaties."""
    state = json.loads(path.read_text(encoding="utf-8"))
    resources = []
    for res in state.get("resources", []):
        for inst in res.get("instances", []):
            resources.append({
                "type": res["type"],
                "name": res["name"],
                "attributes": inst.get("attributes", {}),
            })
    return resources
