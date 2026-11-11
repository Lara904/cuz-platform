# services/api/routers/entity_resolution.py
"""
Métriques de la résolution d'entités probabiliste (P2.5).

  GET /api/v1/tenants/{tenant_id}/entity-resolution/stats

Taux de doublons ESTIMÉ par le modèle (paires >= seuil de fusion auto / nœuds) et paires en attente
de revue humaine (P2.6). Ce n'est pas un taux confirmé : aucune paire n'est encore étiquetée.
Splink est importé à l'appel : l'API démarre même sans ces dépendances installées.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool

from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/entity-resolution",
    tags=["entity-resolution"],
    dependencies=[Depends(require_tenant_scope())],
)


def _stats(tenant_id: str) -> dict | None:
    from packages.entity_resolution.probabilistic_resolver import (
        ProbabilisticResolver,
        compute_stats,
        graph_to_dataframe,
        model_path,
    )

    if not model_path(tenant_id).exists():
        return None
    df = graph_to_dataframe(tenant_id)
    resolver = ProbabilisticResolver(tenant_id)
    resolver.load_model(df)
    return compute_stats(tenant_id, df, resolver)


@router.get("/stats")
async def entity_resolution_stats(tenant_id: str,
                                  _: TokenData = Depends(require_role(Role.VIEWER))):
    stats = await run_in_threadpool(_stats, tenant_id)
    if stats is None:
        raise HTTPException(status_code=409, detail="modèle ER non entraîné pour ce tenant")
    return stats
