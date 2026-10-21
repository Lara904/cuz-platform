# services/api/routers/coverage.py
"""
Couverture CMDB (P1.18).

  GET /api/v1/tenants/{tenant_id}/coverage

cmdb_coverage_pct = part des nœuds vus par une source ET déclarés en CMDB (ServiceNow).
Ce n'est PAS un taux d'inconnu total : l'inconnu n'est pas mesurable.
"""
from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool

from packages.graph.client import Neo4jClient
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}",
    tags=["coverage"],
    dependencies=[Depends(require_tenant_scope())],
)


def _counts(tenant_id: str) -> tuple[int, int]:
    with Neo4jClient.get_driver().session() as session:
        record = session.run(
            """
            MATCH (n:CuzNode {tenant_id: $t})
            RETURN count(n) AS total,
                   sum(CASE WHEN 'servicenow' IN n.sources THEN 1 ELSE 0 END) AS in_cmdb
            """,
            t=tenant_id,
        ).single()
    return record["total"], record["in_cmdb"]


@router.get("/coverage")
async def coverage(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    total, in_cmdb = await run_in_threadpool(_counts, tenant_id)
    return {
        "total_nodes": total,
        "declared_in_cmdb": in_cmdb,
        "not_declared": total - in_cmdb,
        "cmdb_coverage_pct": round(100.0 * in_cmdb / total, 1) if total else None,
    }
