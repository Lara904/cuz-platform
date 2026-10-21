# packages/ingestion/status.py
"""Statut de synchronisation par connecteur (table PostgreSQL connector_status).

Un échec de connecteur ne supprime jamais de nœuds : on met à jour l'état, et le
dashboard affiche l'âge du dernier scan réussi (règle scoring.md).
"""
import asyncpg

import os

DATABASE_URL = os.getenv("DATABASE_URL")  # obligatoire : fourni par .env ou le Secret k8s

SCHEMA = """
CREATE TABLE IF NOT EXISTS connector_status (
    tenant_id          TEXT        NOT NULL,
    source             TEXT        NOT NULL,
    last_attempt       TIMESTAMPTZ,
    last_successful_sync TIMESTAMPTZ,
    last_error         TEXT,
    PRIMARY KEY (tenant_id, source)
);
"""


async def _connect() -> asyncpg.Connection:
    return await asyncpg.connect(DATABASE_URL)


async def init_status_db() -> None:
    conn = await _connect()
    try:
        await conn.execute(SCHEMA)
    finally:
        await conn.close()


async def mark_success(tenant_id: str, source: str) -> None:
    conn = await _connect()
    try:
        await conn.execute(
            """INSERT INTO connector_status (tenant_id, source, last_attempt, last_successful_sync, last_error)
               VALUES ($1, $2, now(), now(), NULL)
               ON CONFLICT (tenant_id, source) DO UPDATE SET
                 last_attempt = now(), last_successful_sync = now(), last_error = NULL""",
            tenant_id, source,
        )
    finally:
        await conn.close()


async def mark_failure(tenant_id: str, source: str, error: str) -> None:
    conn = await _connect()
    try:
        await conn.execute(
            """INSERT INTO connector_status (tenant_id, source, last_attempt, last_error)
               VALUES ($1, $2, now(), $3)
               ON CONFLICT (tenant_id, source) DO UPDATE SET
                 last_attempt = now(), last_error = $3""",
            tenant_id, source, error[:500],
        )
    finally:
        await conn.close()
