# services/api/routers/graph.py
"""
Graphe du tenant pour la vue interactive (P1.12).

  GET /api/v1/tenants/{tenant_id}/graph → nœuds, arêtes et findings ouverts

Les nœuds portent confidence_score et freshness_score (règle 2). Les chemins d'attaque
sont signalés par les findings ouverts : ATTACK-PATH-001-PARTIAL en Phase 1.
"""
import json

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool

from packages.graph.client import Neo4jClient
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope
from services.api.routers.findings import _load

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/graph",
    tags=["graph"],
    dependencies=[Depends(require_tenant_scope())],
)


def _query(tenant_id: str) -> tuple[list[dict], list[dict]]:
    with Neo4jClient.get_driver().session() as session:
        nodes = session.run(
            """
            MATCH (n:CuzNode {tenant_id: $t})
            RETURN n.id AS id, n.name AS name, n.node_type AS node_type,
                   n.sources AS sources, n.confidence_score AS confidence_score,
                   n.freshness_score AS freshness_score, n.owner AS owner,
                   n.attributes AS attributes
            """,
            t=tenant_id,
        ).data()
        edges = session.run(
            """
            MATCH (a:CuzNode {tenant_id: $t})-[r:CUZ_EDGE {tenant_id: $t}]->(b:CuzNode {tenant_id: $t})
            RETURN r.id AS id, a.id AS source_id, b.id AS target_id,
                   r.edge_type AS edge_type, r.confidence_score AS confidence_score
            """,
            t=tenant_id,
        ).data()
    for node in nodes:
        raw = node.pop("attributes") or "{}"
        try:
            node["attributes"] = json.loads(raw)
        except json.JSONDecodeError:
            node["attributes"] = {}
    return nodes, edges


@router.get("/")
async def tenant_graph(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    nodes, edges = await run_in_threadpool(_query, tenant_id)
    findings = await run_in_threadpool(_load, tenant_id)
    open_findings = [
        {"id": f.id, "rule_id": f.rule_id, "severity": f.severity,
         "affected_nodes": f.affected_nodes}
        for f in findings if f.status == "open"
    ]
    return {"nodes": nodes, "edges": edges, "findings": open_findings}
