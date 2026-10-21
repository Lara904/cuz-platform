# packages/connectors/kubernetes/mapper.py
from datetime import UTC, datetime

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness


def _node(tenant_id: str, node_type: NodeType, name: str, external_id: str, attributes: dict,
          tags: dict) -> CuzNode:
    last_seen = datetime.now(UTC)
    return CuzNode(
        tenant_id=tenant_id,
        node_type=node_type,
        name=name,
        external_id=external_id,
        external_ids={"kubernetes": external_id},
        confidence_score=compute_confidence(["kubernetes"]),
        freshness_score=compute_freshness(node_type, last_seen),
        sources=["kubernetes"],
        last_seen=last_seen,
        attributes=attributes,
        tags={"source": "kubernetes", **tags},
    )


class KubernetesMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_cluster(self, raw: dict) -> CuzNode:
        return _node(self.tenant_id, NodeType.CLUSTER, raw["name"], raw["name"],
                     {"cluster_name": raw["name"]}, {"object_type": "cluster"})

    def map_node(self, raw: dict) -> CuzNode:
        """Nœud Kubernetes (worker ou control plane) → SERVER. external_id = nom du nœud,
        stable entre runs et résolvable depuis node_name d'un pod."""
        return _node(self.tenant_id, NodeType.SERVER, raw["name"], raw["name"],
                     {"cluster_name": raw.get("cluster_name"), "k8s_uid": raw.get("uid")},
                     {"object_type": "k8s_node"})

    def map_namespace(self, raw: dict) -> CuzNode:
        return _node(self.tenant_id, NodeType.CLUSTER, f"{raw['cluster_name']}/{raw['name']}",
                     raw["uid"],
                     {"cluster_name": raw["cluster_name"], "namespace": raw["name"]},
                     {"object_type": "namespace"})

    def map_pod(self, raw: dict) -> CuzNode:
        return _node(self.tenant_id, NodeType.CONTAINER, raw["name"], raw["uid"], {
            "namespace": raw["namespace"],
            "cluster_name": raw["cluster_name"],
            "node_name": raw.get("node_name"),
            "privileged": raw.get("privileged", False),
            "run_as_root": raw.get("run_as_root", False),
            "images": raw.get("images", []),
            "is_public_exposed": raw.get("is_public_exposed", False),
            "phase": raw.get("phase"),
        }, {"object_type": "pod"})

    def _edge(self, edge_type: EdgeType, source: CuzNode, target: CuzNode,
              sources: list[str], attributes: dict | None = None) -> CuzEdge:
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=edge_type,
            source_id=source.id,
            target_id=target.id,
            confidence_score=compute_confidence(sources),
            freshness_score=compute_freshness(source.node_type, datetime.now(UTC)),
            sources=sources,
            attributes=attributes or {},
        )

    def map_member_of_edge(self, child: CuzNode, parent: CuzNode) -> CuzEdge:
        """pod → namespace, namespace → cluster."""
        return self._edge(EdgeType.MEMBER_OF, child, parent, ["kubernetes"])

    def map_runs_on_edge(self, pod_node: CuzNode, cluster_node: CuzNode) -> CuzEdge:
        return self._edge(EdgeType.RUNS_ON, pod_node, cluster_node, ["kubernetes"])

    def map_affects_edge(self, vuln_node: CuzNode, pod_node: CuzNode) -> CuzEdge:
        """VULNERABILITY → CONTAINER, si le nom d'image du pod correspond au repo qui déclare la
        dépendance (convention AcmeCorp). Non produit pour legacy-job : son image est ubuntu:20.04."""
        return self._edge(EdgeType.AFFECTS, vuln_node, pod_node, ["kubernetes", "gitea"],
                          {"resolution_method": "image_name_repo_match"})

    def map_exposes_edge(self, pod_node: CuzNode, storage_node: CuzNode) -> CuzEdge:
        """CONTAINER exposé publiquement → STORAGE public. Dépend de is_public_exposed (Service)."""
        return self._edge(EdgeType.EXPOSES, pod_node, storage_node, ["kubernetes", "minio"])
