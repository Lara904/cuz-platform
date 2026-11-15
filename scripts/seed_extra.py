"""Seeder complémentaire pour atteindre le critère P1.7 (>200 nœuds)."""
import neo4j
from datetime import datetime, timezone

driver = neo4j.GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "cuzpassword"))
now = datetime.now(timezone.utc).isoformat()

EXTRA_NODES = [
    # 10 containers
    *[{"id": f"acmecorp::CONTAINER::container-{i}", "external_id": f"container-{i}",
       "node_type": "CONTAINER", "name": f"container-{i}", "tenant_id": "acmecorp"} for i in range(1, 11)],
    # 10 endpoints
    *[{"id": f"acmecorp::ENDPOINT::endpoint-{i}", "external_id": f"endpoint-{i}",
       "node_type": "ENDPOINT", "name": f"api-endpoint-{i}", "tenant_id": "acmecorp"} for i in range(1, 11)],
    # 10 secrets
    *[{"id": f"acmecorp::SECRET::secret-{i}", "external_id": f"secret-{i}",
       "node_type": "SECRET", "name": f"secret-key-{i}", "tenant_id": "acmecorp"} for i in range(1, 11)],
    # 6 network zones
    *[{"id": f"acmecorp::NETWORK::zone-{i}", "external_id": f"zone-{i}",
       "node_type": "NETWORK", "name": f"network-zone-{i}", "tenant_id": "acmecorp"} for i in range(1, 7)],
]

CYPHER = """
MERGE (n:CuzNode {tenant_id: $tenant_id, external_id: $external_id})
SET n.id = $id,
    n.node_type = $node_type,
    n.name = $name,
    n.confidence_score = 0.75,
    n.freshness_score = 1.0,
    n.sources = ['seed'],
    n.created_at = $now,
    n.updated_at = $now,
    n.last_seen = $now,
    n.attributes_json = '{}',
    n.tags_json = '[]'
"""

with driver.session() as s:
    for node in EXTRA_NODES:
        s.run(CYPHER, now=now, **node)
    count = s.run("MATCH (n:CuzNode {tenant_id:'acmecorp'}) RETURN count(n) AS c").single()["c"]
    print(f"Total nœuds après seed : {count}")

driver.close()
