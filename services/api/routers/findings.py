# services/api/routers/findings.py
"""
Findings — exposition REST des détections (P1.10).

  GET    /api/v1/tenants/{tenant_id}/findings/                  → Lister (filtres, pagination)
  GET    /api/v1/tenants/{tenant_id}/findings/stats             → Statistiques
  GET    /api/v1/tenants/{tenant_id}/findings/export/csv        → Export CSV
  POST   /api/v1/tenants/{tenant_id}/findings/refresh           → Relancer la détection
  GET    /api/v1/tenants/{tenant_id}/findings/{id}              → Détail
  GET    /api/v1/tenants/{tenant_id}/findings/{id}/audit        → Historique des statuts
  POST   /api/v1/tenants/{tenant_id}/findings/{id}/acknowledge  → Acquitter (operator)
  POST   /api/v1/tenants/{tenant_id}/findings/{id}/false-positive → Faux positif (operator)
  POST   /api/v1/tenants/{tenant_id}/findings/{id}/resolve      → Résoudre (operator)

Chaque changement de statut est d'abord écrit dans l'audit trail PostgreSQL
(services/api/audit.py, append-only). Si l'écriture échoue, le statut ne change pas.

Déduplication : clé (rule_id, affected_nodes), voir packages/detection/dedup.py.
Stockage des statuts en mémoire pour P1 ; id, statut et justification sont
conservés entre deux calculs grâce à la même clé.
"""
import csv
import io
import logging
from datetime import UTC, datetime
from functools import cache

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from packages.detection.dedup import FindingKey, fingerprint
from packages.detection.models import Finding
from packages.detection.runner import DetectionRunner
from services.api import audit
from services.api.middleware.auth import Role, TokenData, require_role, require_tenant_scope

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/findings",
    tags=["findings"],
    dependencies=[Depends(require_tenant_scope())],
)

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# tenant_id -> {clé de déduplication -> Finding}
_store: dict[str, dict[FindingKey, Finding]] = {}


@cache
def _runner() -> DetectionRunner:
    return DetectionRunner()


def _detect(tenant_id: str) -> list[Finding]:
    return _runner().run_all(tenant_id)


def _load(tenant_id: str, refresh: bool = False) -> list[Finding]:
    if refresh or tenant_id not in _store:
        previous = _store.get(tenant_id, {})
        merged: dict[FindingKey, Finding] = {}
        for finding in _detect(tenant_id):
            key = fingerprint(finding)
            old = previous.get(key)
            if old is not None:  # conserver id, statut, justification entre deux calculs
                finding.id = old.id
                finding.status = old.status
                finding.created_at = old.created_at
                finding.metadata = old.metadata
            merged[key] = finding
        _store[tenant_id] = merged
    findings = list(_store[tenant_id].values())
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.confidence_score))
    return findings


async def _load_async(tenant_id: str, refresh: bool = False) -> list[Finding]:
    # La détection utilise le driver Neo4j synchrone : hors boucle d'événements
    return await run_in_threadpool(_load, tenant_id, refresh)


async def _get(tenant_id: str, finding_id: str) -> Finding:
    finding = next((f for f in await _load_async(tenant_id) if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _transition(
    tenant_id: str, finding_id: str, new_status: str, action: str,
    user: TokenData, metadata: dict[str, object], justification: str | None = None,
    expiry: datetime | None = None,
) -> Finding:
    """Trace le changement dans l'audit PUIS l'applique. Ordre imposé par la règle 4."""
    finding = await _get(tenant_id, finding_id)
    if finding.status == new_status:
        raise HTTPException(status_code=409, detail=f"Finding already {new_status}")
    await audit.record(audit.AuditEntry(
        tenant_id=tenant_id, finding_id=finding.id, rule_id=finding.rule_id,
        action=action, old_status=finding.status, new_status=new_status,
        actor=user.sub, justification=justification, expiry=expiry,
    ))
    finding.status = new_status
    finding.metadata = {**finding.metadata, **metadata}
    finding.updated_at = datetime.now(UTC)
    logger.info("finding_%s tenant=%s finding=%s user=%s", action, tenant_id, finding.id, user.sub)
    return finding


@router.get("/", response_model=list[Finding])
async def list_findings(
    tenant_id: str,
    severity: str | None = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    rule_id: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    _: TokenData = Depends(require_role(Role.VIEWER)),
):
    findings = await _load_async(tenant_id)
    if severity:
        findings = [f for f in findings if f.severity == severity.upper()]
    if rule_id:
        findings = [f for f in findings if f.rule_id == rule_id]
    if status:
        findings = [f for f in findings if f.status == status]
    start = (page - 1) * size
    return findings[start:start + size]


@router.get("/stats")
async def findings_stats(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    findings = await _load_async(tenant_id)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "open": sum(1 for f in findings if f.status == "open"),
    }


@router.get("/export/csv")
async def export_csv(tenant_id: str, _: TokenData = Depends(require_role(Role.VIEWER))):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "rule_id", "severity", "title", "status", "confidence_score",
        "affected_node_names", "remediation_hint", "created_at",
    ])
    writer.writeheader()
    for f in await _load_async(tenant_id):
        writer.writerow({
            "id": f.id,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "title": f.title,
            "status": f.status,
            "confidence_score": f.confidence_score,
            "affected_node_names": ",".join(f.affected_node_names),
            "remediation_hint": f.remediation_hint,
            "created_at": f.created_at.isoformat(),
        })
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{tenant_id}.csv"},
    )


@router.post("/refresh")
async def refresh_findings(tenant_id: str, user: TokenData = Depends(require_role(Role.OPERATOR))):
    count = len(await _load_async(tenant_id, refresh=True))
    logger.info("findings_refresh tenant=%s count=%d user=%s", tenant_id, count, user.sub)
    return {"total": count}


@router.get("/{finding_id}", response_model=Finding)
async def get_finding(tenant_id: str, finding_id: str,
                      _: TokenData = Depends(require_role(Role.VIEWER))):
    return await _get(tenant_id, finding_id)


@router.get("/{finding_id}/audit")
async def finding_audit(tenant_id: str, finding_id: str,
                        _: TokenData = Depends(require_role(Role.VIEWER))):
    await _get(tenant_id, finding_id)  # 404 si le finding n'existe pas
    return await audit.history(tenant_id, finding_id)


@router.post("/{finding_id}/acknowledge")
async def acknowledge(
    tenant_id: str,
    finding_id: str,
    justification: str = "",
    expiry: datetime | None = None,
    user: TokenData = Depends(require_role(Role.OPERATOR)),
):
    await _transition(
        tenant_id, finding_id, "acknowledged", "acknowledged", user,
        metadata={"justification": justification,
                  "expiry": expiry.isoformat() if expiry else None,
                  "acknowledged_by": user.sub},
        justification=justification, expiry=expiry,
    )
    return {"status": "acknowledged", "finding_id": finding_id}


@router.post("/{finding_id}/false-positive")
async def false_positive(
    tenant_id: str,
    finding_id: str,
    reason: str = "",
    user: TokenData = Depends(require_role(Role.OPERATOR)),
):
    await _transition(
        tenant_id, finding_id, "false_positive", "false_positive", user,
        metadata={"reason": reason, "marked_by": user.sub}, justification=reason,
    )
    return {"status": "false_positive", "finding_id": finding_id}


@router.post("/{finding_id}/resolve")
async def resolve(
    tenant_id: str,
    finding_id: str,
    justification: str = "",
    user: TokenData = Depends(require_role(Role.OPERATOR)),
):
    await _transition(
        tenant_id, finding_id, "resolved", "resolved", user,
        metadata={"resolution": justification, "resolved_by": user.sub},
        justification=justification,
    )
    return {"status": "resolved", "finding_id": finding_id}
