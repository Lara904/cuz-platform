# services/api/audit.py
"""
Audit trail des findings — RÈGLE 4 (CLAUDE.md) : append-only, aucune suppression.

Chaque changement de statut d'un finding (acquittement, faux positif, résolution)
produit une ligne dans finding_audit. La table est protégée par un trigger qui
refuse UPDATE, DELETE et TRUNCATE. Une écriture d'audit qui échoue doit faire
échouer l'action métier : pas de changement d'état sans trace.
"""
from dataclasses import dataclass
from datetime import datetime

import asyncpg

from services.api.routers.tenants import DATABASE_URL  # une seule source de config

_pool: asyncpg.Pool | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_audit (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      TEXT        NOT NULL,
    finding_id     TEXT        NOT NULL,
    rule_id        TEXT        NOT NULL,
    action         TEXT        NOT NULL,
    old_status     TEXT        NOT NULL,
    new_status     TEXT        NOT NULL,
    actor          TEXT        NOT NULL,
    justification  TEXT,
    expiry         TIMESTAMPTZ,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION finding_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'finding_audit is append-only (RÈGLE 4)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS finding_audit_no_update_delete ON finding_audit;
CREATE TRIGGER finding_audit_no_update_delete
    BEFORE UPDATE OR DELETE ON finding_audit
    FOR EACH ROW EXECUTE FUNCTION finding_audit_append_only();

DROP TRIGGER IF EXISTS finding_audit_no_truncate ON finding_audit;
CREATE TRIGGER finding_audit_no_truncate
    BEFORE TRUNCATE ON finding_audit
    FOR EACH STATEMENT EXECUTE FUNCTION finding_audit_append_only();

CREATE INDEX IF NOT EXISTS finding_audit_by_finding ON finding_audit (tenant_id, finding_id, occurred_at);
"""


@dataclass(frozen=True)
class AuditEntry:
    tenant_id: str
    finding_id: str
    rule_id: str
    action: str
    old_status: str
    new_status: str
    actor: str
    justification: str | None = None
    expiry: datetime | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
    return _pool


async def init_audit_db() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


async def record(entry: AuditEntry) -> None:
    """Insère une ligne d'audit. Lève une exception si l'insertion échoue."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO finding_audit
               (tenant_id, finding_id, rule_id, action, old_status, new_status,
                actor, justification, expiry)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
            entry.tenant_id, entry.finding_id, entry.rule_id, entry.action,
            entry.old_status, entry.new_status, entry.actor,
            entry.justification, entry.expiry,
        )


async def history(tenant_id: str, finding_id: str) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT action, old_status, new_status, actor, justification, expiry, occurred_at
               FROM finding_audit WHERE tenant_id = $1 AND finding_id = $2
               ORDER BY occurred_at, id""",
            tenant_id, finding_id,
        )
    return [dict(r) for r in rows]


async def recent(tenant_id: str, limit: int = 20) -> list[dict]:
    """Derniers événements d'audit du tenant, du plus récent au plus ancien."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT finding_id, rule_id, action, actor, occurred_at AS created_at
               FROM finding_audit WHERE tenant_id = $1
               ORDER BY occurred_at DESC, id DESC LIMIT $2""",
            tenant_id, limit,
        )
    return [dict(r) for r in rows]
