# services/api/routers/entity_resolution.py
"""
Résolution d'entités probabiliste : métriques (P2.5) et validation humaine des paires (P2.6).

  GET  /api/v1/tenants/{tenant_id}/entity-resolution/stats
  GET  /api/v1/tenants/{tenant_id}/entity-resolution/pairs            paires en zone grise 0.60-0.92
  GET  /api/v1/tenants/{tenant_id}/entity-resolution/pairs/{pair_id}
  POST /api/v1/tenants/{tenant_id}/entity-resolution/pairs/{pair_id}/decide   (OPERATOR)
  GET  /api/v1/tenants/{tenant_id}/entity-resolution/decisions/stats

La décision « merge » est ENREGISTRÉE (er_decisions, append-only, RÈGLE 4) mais ne fusionne rien dans
Neo4j : seul le GraphWriter écrit dans le graphe (RÈGLE 1) et il n'a pas encore d'opération de fusion.
Le relecteur est l'identité du token, jamais une valeur fournie par le client.
Splink est importé à l'appel : l'API démarre même sans ces dépendances installées.
"""

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from services.api import er_audit
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/entity-resolution",
    tags=["entity-resolution"],
    dependencies=[Depends(require_tenant_scope())],
)

FINAL_DECISIONS = ("merge", "reject")  # « flag » laisse la paire en attente


class PairDecision(BaseModel):
    decision: Literal["merge", "reject", "flag"]
    note: str | None = None


def _load_model(tenant_id: str):
    from packages.entity_resolution.probabilistic_resolver import (
        ProbabilisticResolver,
        graph_to_dataframe,
        model_path,
    )

    if not model_path(tenant_id).exists():
        return None
    df = graph_to_dataframe(tenant_id)
    resolver = ProbabilisticResolver(tenant_id)
    resolver.load_model(df)
    return df, resolver


def _stats(tenant_id: str) -> dict | None:
    from packages.entity_resolution.probabilistic_resolver import compute_stats

    loaded = _load_model(tenant_id)
    if loaded is None:
        return None
    df, resolver = loaded
    return compute_stats(tenant_id, df, resolver)


def _node_details(tenant_id: str, ids: list[str]) -> dict[str, dict]:
    from packages.graph.client import Neo4jClient

    with Neo4jClient.get_driver().session() as session:
        rows = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) WHERE n.id IN $ids "
            "RETURN n.id AS id, n.name AS name, n.node_type AS node_type, n.sources AS sources, "
            "n.confidence_score AS confidence_score, n.freshness_score AS freshness_score, "
            "n.attributes AS attributes, n.tags AS tags",
            t=tenant_id,
            ids=ids,
        ).data()
    for r in rows:
        r["attributes"] = json.loads(r["attributes"] or "{}")
        r["tags"] = json.loads(r["tags"] or "{}")
    return {r["id"]: r for r in rows}


def _review_pairs(tenant_id: str) -> list[dict] | None:
    """Paires de la zone grise (0.60-0.92) avec le détail complet des deux nœuds."""
    from packages.entity_resolution.probabilistic_resolver import ProbabilisticResolver

    loaded = _load_model(tenant_id)
    if loaded is None:
        return None
    df, resolver = loaded
    review = ProbabilisticResolver.classify(resolver.predict_candidate_pairs(df))[
        "needs_human_review"
    ]
    review = review.sort_values("match_probability", ascending=False)
    ids = sorted({*review["unique_id_l"], *review["unique_id_r"]})
    nodes = _node_details(tenant_id, ids)
    pairs = []
    for row in review.itertuples():
        if row.unique_id_l not in nodes or row.unique_id_r not in nodes:
            continue  # nœud disparu du graphe depuis le calcul
        pairs.append(
            {
                "pair_id": er_audit.pair_id_for(row.unique_id_l, row.unique_id_r),
                "match_probability": round(float(row.match_probability), 4),
                "node_a": nodes[row.unique_id_l],
                "node_b": nodes[row.unique_id_r],
            }
        )
    return pairs


async def _pending(tenant_id: str) -> list[dict]:
    pairs = await run_in_threadpool(_review_pairs, tenant_id)
    if pairs is None:
        raise HTTPException(status_code=409, detail="modèle ER non entraîné pour ce tenant")
    latest = await er_audit.latest_decisions(tenant_id)
    pending = []
    for pair in pairs:
        last = latest.get(pair["pair_id"])
        if last and last["decision"] in FINAL_DECISIONS:
            continue
        pending.append({**pair, "flagged": bool(last and last["decision"] == "flag")})
    return pending


@router.get("/stats")
async def entity_resolution_stats(
    tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))
):
    stats = await run_in_threadpool(_stats, tenant_id)
    if stats is None:
        raise HTTPException(status_code=409, detail="modèle ER non entraîné pour ce tenant")
    return stats


@router.get("/pairs")
async def list_pending_pairs(
    tenant_id: str, page: int = 1, size: int = 20, _: TokenData = Depends(require_role(Role.VIEWER))
):
    if page < 1 or not 1 <= size <= 100:
        raise HTTPException(status_code=400, detail="page >= 1 et 1 <= size <= 100")
    pending = await _pending(tenant_id)
    start = (page - 1) * size
    return {
        "total": len(pending),
        "page": page,
        "size": size,
        "pairs": pending[start : start + size],
    }


@router.get("/pairs/{pair_id}")
async def get_pair(tenant_id: str, pair_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    for pair in await _pending(tenant_id):
        if pair["pair_id"] == pair_id:
            return pair
    raise HTTPException(status_code=404, detail="Pair not found")


@router.post("/pairs/{pair_id}/decide")
async def decide_pair(
    tenant_id: str,
    pair_id: str,
    body: PairDecision,
    user: TokenData = Depends(require_role(Role.OPERATOR)),
):
    pair = next((p for p in await _pending(tenant_id) if p["pair_id"] == pair_id), None)
    if pair is None:
        latest = await er_audit.latest_decisions(tenant_id)
        if latest.get(pair_id, {}).get("decision") in FINAL_DECISIONS:
            raise HTTPException(status_code=409, detail="Pair already decided")
        raise HTTPException(status_code=404, detail="Pair not found")
    # RÈGLE 4 : la trace est écrite avant toute réponse de succès ; échec d'écriture = échec de l'action
    await er_audit.record(
        er_audit.Decision(
            tenant_id=tenant_id,
            pair_id=pair_id,
            node_a_id=pair["node_a"]["id"],
            node_b_id=pair["node_b"]["id"],
            match_probability=pair["match_probability"],
            decision=body.decision,
            reviewer=user.sub,
            note=body.note,
        )
    )
    return {
        "status": "recorded",
        "pair_id": pair_id,
        "decision": body.decision,
        "graph_merge_applied": False,
    }


@router.get("/decisions/stats")
async def decisions_stats(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    return await er_audit.stats(tenant_id)
