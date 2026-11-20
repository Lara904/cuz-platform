# services/api/routers/audit.py
"""Consultation de l'audit trail JIT/remédiation (P2.12).

  GET /api/v1/tenants/{tenant_id}/audit/events      → Liste paginée, filtrable par finding_id
  GET /api/v1/tenants/{tenant_id}/audit/export/csv   → Export conforme pour le régulateur

Accès réservé aux rôles VIEWER+ (role documenté comme "Auditeur / équipe conformité",
cf. services/api/middleware/auth.py) --- même garde-fou RBAC que les autres routers de
lecture (dashboard.py, findings.py). Le guide P2.12 d'origine ne posait aucune dépendance
d'auth sur ces endpoints : un export d'audit destiné au régulateur est justement le genre
de donnée qui ne doit jamais être accessible sans authentification (cf. DECISIONS.md
DEC-007).
"""

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from packages.audit.audit_sink import PostgresAuditSink
from services.api.middleware.auth import Role, require_role, require_tenant_scope

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/audit",
    tags=["audit"],
    dependencies=[Depends(require_tenant_scope())],
)


@router.get("/events")
async def list_audit_events(
    tenant_id: str,
    finding_id: str | None = None,
    since: datetime | None = None,
    page: int = 1,
    size: int = 50,
    _: object = Depends(require_role(Role.VIEWER)),
) -> dict:
    sink = PostgresAuditSink(tenant_id=tenant_id)
    events = await sink.export_for_regulator(since=since)
    if finding_id:
        events = [e for e in events if e.get("finding_id") == finding_id]
    start = (page - 1) * size
    return {"total": len(events), "events": events[start : start + size]}


@router.get("/export/csv")
async def export_audit_csv(
    tenant_id: str,
    _: object = Depends(require_role(Role.VIEWER)),
) -> StreamingResponse:
    sink = PostgresAuditSink(tenant_id=tenant_id)
    events = await sink.export_for_regulator()
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=["id", "action_id", "event_type", "actor", "finding_id", "created_at"]
    )
    writer.writeheader()
    for e in events:
        writer.writerow({k: e.get(k) for k in writer.fieldnames})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_{tenant_id}.csv"},
    )
