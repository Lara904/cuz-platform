# packages/connectors/servicenow/mapper.py
from datetime import datetime, timezone
from typing import Optional
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType
from packages.core.scoring import compute_confidence, compute_freshness

TABLE_TO_NODE_TYPE = {
    "cmdb_ci_server":     NodeType.SERVER,
    "cmdb_ci_appl":       NodeType.APPLICATION,
    "cmdb_ci_database":   NodeType.DATABASE,
    "cmdb_ci_ip_network": NodeType.NETWORK,
    "cmdb_ci_service":    NodeType.APPLICATION,
    "cmdb_rel_ci":        None,  # arête — traité séparément
}

class ServiceNowMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_ci(self, table: str, rec: dict) -> Optional[CuzNode]:
        node_type = TABLE_TO_NODE_TYPE.get(table)
        if not node_type:
            return None
        name = rec.get("name") or rec.get("sys_id", "unknown")
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=node_type,
            name=name,
            external_id=rec.get("sys_id"),
            external_ids={"servicenow": rec.get("sys_id", "")},
            confidence_score=compute_confidence(["servicenow"]),
            freshness_score=compute_freshness(node_type, last_seen),
            sources=["servicenow"],
            last_seen=last_seen,
            attributes={
                "operational_status": rec.get("operational_status"),
                "environment":        rec.get("environment"),
                "sys_class_name":     rec.get("sys_class_name"),
                "ip_address":         rec.get("ip_address"),
                "os":                 rec.get("os"),
                "exit_plan_status":   rec.get("exit_plan_status"),
                "vendor":             rec.get("vendor"),
                "support_group":      rec.get("support_group"),
            },
            tags={
                "source":      "servicenow",
                "cmdb_table":  table,
            },
        )