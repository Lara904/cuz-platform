# services/api/routers/exports.py
"""
Exports réglementaires (P1.15).

  GET /api/v1/tenants/{tenant_id}/exports/dora/ict-register → registre ICT (CSV, format ESA)

Source : nœuds THIRD_PARTY et leurs arêtes SUPPORTS. Une arête SUPPORTS vers un
BusinessFunction arrive avec P1.16 ; d'ici là la colonne supported_function est vide
si aucune arête SUPPORTS n'a été produite. exit_plan_status est lu en propriété native.
"""
import csv
import io
import json

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from packages.graph.client import Neo4jClient
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/exports",
    tags=["exports"],
    dependencies=[Depends(require_tenant_scope())],
)

DORA_CYPHER = """
MATCH (tp:CuzNode {tenant_id: $tenant_id, node_type: 'THIRD_PARTY'})
OPTIONAL MATCH (tp)-[:CUZ_EDGE {edge_type: 'SUPPORTS'}]->(bf:CuzNode {tenant_id: $tenant_id})
RETURN tp.name AS provider_name,
       tp.attributes AS provider_attrs,
       tp.exit_plan_status AS exit_plan_status,
       collect(bf.name) AS supported_functions
ORDER BY provider_name
"""

FIELDNAMES = ["provider_name", "provider_type", "country", "criticality", "exit_plan_status",
              "supported_function", "contract_end_date", "substitutability", "concentration_risk"]


def _load_json(raw: str | None) -> dict:
    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _rows(tenant_id: str) -> list[dict]:
    with Neo4jClient.get_driver().session() as session:
        records = session.run(DORA_CYPHER, tenant_id=tenant_id).data()
    rows: list[dict] = []
    for rec in records:
        attrs = _load_json(rec["provider_attrs"])
        functions = [f for f in rec["supported_functions"] if f] or [""]
        for function in functions:  # un prestataire peut soutenir plusieurs fonctions
            rows.append({
                "provider_name": rec["provider_name"],
                "provider_type": attrs.get("provider_type", ""),
                "country": attrs.get("country", ""),
                "criticality": attrs.get("criticality", ""),
                "exit_plan_status": rec["exit_plan_status"] or "NOT_SET",
                "supported_function": function,
                "contract_end_date": attrs.get("contract_end_date", ""),
                "substitutability": attrs.get("substitutability", ""),
                "concentration_risk": attrs.get("concentration_risk", ""),
            })
    return rows


def _csv(rows: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@router.get("/dora/ict-register")
async def dora_ict_register(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    rows = await run_in_threadpool(_rows, tenant_id)
    return StreamingResponse(
        iter([_csv(rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=dora_ict_register_{tenant_id}.csv"},
    )
