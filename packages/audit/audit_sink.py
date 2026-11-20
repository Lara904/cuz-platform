# packages/audit/audit_sink.py
"""RÈGLE 4 étendue (P2.12) aux actions JIT/remédiation des agents (P2.11) : append-only
strict dans PostgreSQL, implémente l'interface attendue par BaseRemediationAgent
(packages/agents/base_agent.py, AuditSink). Table dédiée (audit_events) --- distincte de
finding_audit (P1, changements de statut d'un finding) et de er_decisions (P2.6, décisions
ER) : un périmètre, une table, même principe que RÈGLE 6 pour les agents.

Trois écarts corrigés par rapport au guide P2.12 (cf. DECISIONS.md DEC-007), tous les
trois pour rester cohérent avec le pattern déjà en place et vérifié dans ce repo
(services/api/audit.py, services/api/er_audit.py) plutôt que d'introduire un deuxième
mécanisme différent pour la même garantie :

1. Append-only appliqué par un TRIGGER PostgreSQL qui lève une exception sur
   UPDATE/DELETE/TRUNCATE --- pas par un `REVOKE DELETE, UPDATE ... FROM cuz_app_role`.
   Un rôle `cuz_app_role` n'existe nulle part dans ce repo/l'infra (docker-compose utilise
   POSTGRES_USER=cuzuser) --- un REVOKE sur un rôle inexistant échoue à l'exécution. Le
   trigger protège au niveau de la table elle-même, quel que soit le rôle de connexion.

2. Schéma appliqué via un init_db() idempotent (CREATE TABLE IF NOT EXISTS + trigger),
   appelé une fois au démarrage de l'API --- pas via un fichier
   infra/db/migrations/V002__audit_events.sql : ce répertoire et tout outil de migration
   (alembic, flyway) n'existent pas dans ce repo. C'est exactement le mécanisme déjà en
   place pour finding_audit/er_decisions (cf. services/api/main.py, init_audit_db()).

3. record() est une coroutine AWAITÉE par BaseRemediationAgent.remediate(), jamais un
   asyncio.create_task() fire-and-forget : le docstring de services/api/audit.py pose déjà
   le principe ("une écriture d'audit qui échoue doit faire échouer l'action") --- un
   append non attendu pourrait silencieusement disparaître (DB indisponible, process tué
   juste après le retour de remediate()), ce qui contredit directement RÈGLE 4.
"""

from datetime import datetime
from typing import Any

import asyncpg

DATABASE_URL_DEFAULT = "postgresql://cuz:cuzpassword@localhost:5432/cuzdb"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    action_id       TEXT NOT NULL,
    event_type      TEXT NOT NULL,          -- jit_credential_acquired | remediation_executed | jit_credential_revoked
    actor           TEXT NOT NULL,          -- nom de classe de l'agent OU id d'un reviewer humain
    finding_id      TEXT,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_finding ON audit_events (finding_id);

-- RÈGLE 4 : append-only strict appliqué par trigger, même mécanisme que finding_audit
-- (services/api/audit.py) et er_decisions (services/api/er_audit.py) --- pas un GRANT/REVOKE
-- lié à un rôle applicatif particulier, qui n'existe pas dans ce repo.
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (RÈGLE 4)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events;
CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
"""

# Pool partagé au niveau du module --- même pattern que services.api.audit.get_pool() :
# une seule table, un seul pool, filtré par tenant_id en SQL (pas un pool par tenant).
_pool: asyncpg.Pool | None = None


async def get_pool(dsn: str = DATABASE_URL_DEFAULT) -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    return _pool


async def init_db(dsn: str = DATABASE_URL_DEFAULT) -> None:
    pool = await get_pool(dsn)
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


class PostgresAuditSink:
    """Implémente l'interface AuditSink attendue par BaseRemediationAgent (P2.11) :
    async def record(event_type, action_id, payload, finding_id=None). Append-only
    garanti au niveau SQL (trigger, cf. SCHEMA) ET au niveau applicatif (aucune méthode
    delete()/update() exposée ici)."""

    def __init__(self, dsn: str = DATABASE_URL_DEFAULT, tenant_id: str = "", actor: str = "system"):
        self.dsn = dsn
        self.tenant_id = tenant_id
        self.actor = actor

    async def record(
        self,
        event_type: str,
        action_id: str,
        payload: dict[str, Any],
        finding_id: str | None = None,
    ) -> None:
        """Insère une ligne d'audit et ATTEND la confirmation d'écriture avant de
        retourner --- lève une exception si l'insertion échoue (DEC-007 : jamais de
        fire-and-forget sur un audit trail)."""
        import json

        pool = await get_pool(self.dsn)
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_events "
                "(tenant_id, action_id, event_type, actor, finding_id, payload) "
                "VALUES ($1, $2, $3, $4, $5, $6)",
                self.tenant_id,
                action_id,
                event_type,
                self.actor,
                finding_id,
                json.dumps(payload),
            )

    async def export_for_regulator(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Critère de sortie P2.12 : export conforme, consultable par un auditeur externe
        sans accès direct à la base. Ordonné chronologiquement (ASC) --- un export
        d'audit se lit dans l'ordre des faits, pas dans l'ordre d'insertion inverse."""
        pool = await get_pool(self.dsn)
        query = "SELECT * FROM audit_events WHERE tenant_id = $1"
        params: list[Any] = [self.tenant_id]
        if since is not None:
            query += " AND created_at >= $2"
            params.append(since)
        query += " ORDER BY created_at ASC"
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows]
