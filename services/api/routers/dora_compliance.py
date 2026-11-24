# services/api/routers/dora_compliance.py
"""
Module DORA complet (P2.13) : page /compliance/dora --- registre des tiers enrichi des
fonctions supportées, détection du risque de concentration (DORA-CONCENTRATION-001, P2.13
DEC-008), export réglementaire.

  GET /api/v1/tenants/{tenant_id}/compliance/dora/register           → registre JSON complet
  GET /api/v1/tenants/{tenant_id}/compliance/dora/concentration-risk → findings DORA-CONCENTRATION-001
  GET /api/v1/tenants/{tenant_id}/compliance/dora/export/esa         → même export CSV que
      /exports/dora/ict-register (P1.15) --- source unique de vérité, jamais un second schéma
      CSV concurrent (voir DEC-008 : le guide en proposait un différent, divergent du format déjà
      en place).

⚠️ Limite assumée (DEC-008), héritée du guide lui-même : sans l'instance ServiceNow (désactivée
depuis P2.1) ni le mapping cmdb_rel_ci → SUPPORTS (toujours pas écrit, FIX-1/P1.16), les fonctions
supportées listées ici ne reflètent que les BUSINESS_PROCESS posés manuellement par
business_process_loader.py, jamais une relation CMDB réelle. Le registre et la détection
fonctionnent correctement sur les arêtes SUPPORTS qui existent, quelle que soit leur origine ---
mais leur complétude dépend de cette donnée d'entrée, hors périmètre de ce fichier.
"""

import json

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from packages.detection.rules import make_rule
from packages.detection.rules.dora import DORA_CONCENTRATION_001
from packages.graph.client import Neo4jClient
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope
from services.api.routers.exports import _csv as _ict_csv
from services.api.routers.exports import _rows as _ict_rows

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/compliance/dora",
    tags=["dora-compliance"],
    dependencies=[Depends(require_tenant_scope())],
)

_rule_dora_concentration_001 = make_rule(DORA_CONCENTRATION_001)

REGISTER_CYPHER = """
MATCH (tp:CuzNode {tenant_id: $tenant_id, node_type: 'THIRD_PARTY'})
OPTIONAL MATCH (tp)-[:CUZ_EDGE {edge_type: 'SUPPORTS'}]->(bf:CuzNode {tenant_id: $tenant_id})
RETURN tp.name AS provider_name,
       tp.attributes AS provider_attrs,
       tp.exit_plan_status AS exit_plan_status,
       collect(DISTINCT bf.name) AS supported_functions
ORDER BY provider_name
"""


def _load_json(raw: str | None) -> dict:
    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _register_rows(tenant_id: str) -> list[dict]:
    """Une ligne par prestataire (pas une par fonction, contrairement à l'export CSV ESA
    de exports.py qui doit rester tabulaire) : adapté à l'affichage de la page /compliance/dora,
    pas à un export plat."""
    with Neo4jClient.get_driver().session() as session:
        records = session.run(REGISTER_CYPHER, tenant_id=tenant_id).data()
    rows: list[dict] = []
    for rec in records:
        attrs = _load_json(rec["provider_attrs"])
        rows.append(
            {
                "provider_name": rec["provider_name"],
                "provider_type": attrs.get("provider_type", ""),
                "exit_plan_status": rec["exit_plan_status"] or "NOT_SET",
                "last_review_date": attrs.get("last_review_date", ""),
                "supported_functions": [f for f in rec["supported_functions"] if f],
            }
        )
    return rows


def _concentration_findings(tenant_id: str) -> list[dict]:
    with Neo4jClient.get_driver().session() as session:
        findings = _rule_dora_concentration_001(session, tenant_id)
    return [f.model_dump() for f in findings]


@router.get("/register")
async def dora_register(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    rows = await run_in_threadpool(_register_rows, tenant_id)
    return {"register": rows}


@router.get("/concentration-risk")
async def concentration_risk(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    findings = await run_in_threadpool(_concentration_findings, tenant_id)
    return {"findings": findings}


@router.get("/export/esa")
async def export_esa_format(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    """Réutilise le même export que GET /exports/dora/ict-register (P1.15) : un seul schéma
    CSV « format ESA » dans tout le projet, jamais deux implémentations divergentes."""
    rows = await run_in_threadpool(_ict_rows, tenant_id)
    return StreamingResponse(
        iter([_ict_csv(rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=dora_esa_{tenant_id}.csv"},
    )
