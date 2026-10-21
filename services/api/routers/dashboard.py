# services/api/routers/dashboard.py
"""
Données du dashboard (P1.11).

  GET /api/v1/tenants/{tenant_id}/dashboard/stats      → KPIs (nœuds, findings par sévérité)
  GET /api/v1/tenants/{tenant_id}/dashboard/freshness  → Fraîcheur par source (heatmap)

health_score = moyenne, sur tous les nœuds du tenant, de (confidence_score + freshness_score) / 2,
arrondie à 2 décimales (0..1). Indicateur de qualité des données, pas de sécurité.
"""
from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool

from packages.graph.client import Neo4jClient
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope
from services.api import audit
from services.api.routers.findings import _load

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_tenant_scope())],
)

FRESH_THRESHOLD = 0.8
STALE_THRESHOLD = 0.2


def _node_count(tenant_id: str) -> int:
    with Neo4jClient.get_driver().session() as session:
        return session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) RETURN count(n) AS c", t=tenant_id
        ).single()["c"]


def _health_score(tenant_id: str) -> float | None:
    with Neo4jClient.get_driver().session() as session:
        value = session.run(
            """
            MATCH (n:CuzNode {tenant_id: $t})
            RETURN avg((n.confidence_score + n.freshness_score) / 2.0) AS score
            """,
            t=tenant_id,
        ).single()["score"]
    return None if value is None else round(value, 2)


def _freshness(tenant_id: str) -> list[dict]:
    # Une ligne par source principale (sources[0]) : moyenne et répartition des fraîcheurs
    with Neo4jClient.get_driver().session() as session:
        rows = session.run(
            """
            MATCH (n:CuzNode {tenant_id: $t})
            WITH n.sources[0] AS source, n.freshness_score AS f
            RETURN source,
                   count(*) AS nodes,
                   avg(f) AS avg_freshness,
                   sum(CASE WHEN f >= $fresh THEN 1 ELSE 0 END) AS fresh,
                   sum(CASE WHEN f < $fresh AND f >= $stale THEN 1 ELSE 0 END) AS aging,
                   sum(CASE WHEN f < $stale THEN 1 ELSE 0 END) AS stale
            ORDER BY source
            """,
            t=tenant_id, fresh=FRESH_THRESHOLD, stale=STALE_THRESHOLD,
        ).data()
    return [{
        "source": r["source"] or "inconnue",
        "nodes": r["nodes"],
        "avg_freshness": round(r["avg_freshness"] or 0.0, 3),
        "fresh": r["fresh"], "aging": r["aging"], "stale": r["stale"],
    } for r in rows]


@router.get("/stats")
async def dashboard_stats(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    findings = await run_in_threadpool(_load, tenant_id)
    node_count = await run_in_threadpool(_node_count, tenant_id)
    health = await run_in_threadpool(_health_score, tenant_id)
    by_severity: dict[str, int] = {}
    for f in findings:
        if f.status == "open":
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "node_count": node_count,
        "by_severity": by_severity,
        "open": sum(by_severity.values()),
        "health_score": health,
    }


@router.get("/timeline")
async def dashboard_timeline(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    """20 derniers changements de statut, du plus récent au plus ancien (source : finding_audit)."""
    return await audit.recent(tenant_id, limit=20)


@router.get("/freshness")
async def dashboard_freshness(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    return await run_in_threadpool(_freshness, tenant_id)
