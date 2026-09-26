# packages/connectors/gitea/mapper.py
from datetime import datetime, timezone
from typing import List, Tuple
from packages.core.models.node import CuzNode
from packages.core.models.edge import CuzEdge
from packages.core.models.enums import NodeType, EdgeType
from packages.core.scoring import compute_confidence, compute_freshness

class GiteaMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_repo(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.REPOSITORY,
            name=raw["name"],
            external_id=raw["repo_id"],
            external_ids={"gitea": raw["repo_id"]},
            confidence_score=compute_confidence(["gitea"]),
            freshness_score=compute_freshness(NodeType.REPOSITORY, last_seen),
            sources=["gitea"],
            last_seen=last_seen,
            attributes={
                "full_name":      raw.get("full_name"),
                "private":        raw.get("private", True),
                "default_branch": raw.get("default_branch", "main"),
                "owner":          raw.get("owner"),
            },
            tags={"source": "gitea"},
        )

    def map_dependency(self, dep: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        dep_name = f"{dep['name']}@{dep['version']}"
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.VULNERABILITY,
            name=dep_name,
            external_id=dep_name,
            external_ids={"gitea": dep_name},
            confidence_score=compute_confidence(["gitea"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["gitea"],
            last_seen=last_seen,
            attributes={
                "package_name": dep["name"],
                "version":      dep["version"],
                "ecosystem":    dep.get("ecosystem", "unknown"),
            },
            tags={"source": "gitea", "node_subtype": "dependency"},
        )

    def map_repo_dependency_edge(
        self, repo_node: CuzNode, dep_node: CuzNode
    ) -> CuzEdge:
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.DEPENDS_ON,
            source_id=repo_node.id,
            target_id=dep_node.id,
            confidence_score=compute_confidence(["gitea"]),
            freshness_score=compute_freshness(NodeType.REPOSITORY, last_seen),
            sources=["gitea"],
        )