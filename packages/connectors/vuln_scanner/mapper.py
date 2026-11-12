# packages/connectors/vuln_scanner/mapper.py
from datetime import UTC, datetime
from typing import Any

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness


class VulnScannerMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_cve(self, rec: dict[str, Any]) -> CuzNode:
        last_seen = datetime.now(UTC)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.VULNERABILITY,
            name=rec["cve_id"],
            external_id=rec["cve_id"],
            external_ids={"vuln_scanner": rec["cve_id"]},
            confidence_score=compute_confidence(["vuln_scanner"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["vuln_scanner"],
            last_seen=last_seen,
            attributes={
                "cve_id": rec["cve_id"],
                "package": rec.get("package"),
                "version_affected": rec.get("version_affected"),
                "cvss_score": rec.get("cvss_score"),
                "epss_score": rec.get("epss_score"),
                "epss_percentile": rec.get("epss_percentile"),
                "epss_source": rec.get("epss_source"),
                "patch_status": rec.get("patch_status", "unpatched"),
                "description": rec.get("description"),
            },
            tags={"source": "vuln_scanner", "node_subtype": "cve"},
        )

    def map_affects_edge(
        self,
        cve_node: CuzNode,
        target_node: CuzNode,
        resolution_method: str = "package_version_match",
    ) -> CuzEdge:
        last_seen = datetime.now(UTC)
        sources = sorted({*cve_node.sources, *target_node.sources})
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.AFFECTS,
            source_id=cve_node.id,
            target_id=target_node.id,
            confidence_score=compute_confidence(sources),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=sources,
            attributes={"resolution_method": resolution_method},
        )
