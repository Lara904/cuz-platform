"""
services/api/routers/connectors.py

CRUD connecteurs par tenant.

Endpoints :
  GET    /api/v1/tenants/{tenant_id}/connectors              → Lister
  POST   /api/v1/tenants/{tenant_id}/connectors              → Créer
  GET    /api/v1/tenants/{tenant_id}/connectors/{id}         → Détail
  PUT    /api/v1/tenants/{tenant_id}/connectors/{id}         → Mettre à jour
  DELETE /api/v1/tenants/{tenant_id}/connectors/{id}         → Supprimer
  POST   /api/v1/tenants/{tenant_id}/connectors/{id}/test    → Tester la connexion
"""
import os
import uuid
from datetime import datetime, timezone
from typing import List

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from services.api.middleware.auth import Role, TokenData, require_role
from services.api.models.connector import (
    ConnectorCreate,
    ConnectorResponse,
    ConnectorStatus,
    ConnectorTestResult,
    ConnectorUpdate,
)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/connectors", tags=["connectors"])

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cuz:cuzpassword@localhost:5432/cuzdb")

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    return _pool


async def init_db():
    """Crée la table connectors si elle n'existe pas."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS connectors (
                id          TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                type        TEXT NOT NULL,
                name        TEXT NOT NULL,
                config      JSONB NOT NULL DEFAULT '{}',
                status      TEXT NOT NULL DEFAULT 'pending',
                last_sync   TIMESTAMPTZ,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


def _check_tenant_scope(current_user: TokenData, tenant_id: str):
    if current_user.role != Role.TENANT_ADMIN and current_user.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé.")


def row_to_connector(row: asyncpg.Record) -> ConnectorResponse:
    return ConnectorResponse(
        id=row["id"],
        tenant_id=row["tenant_id"],
        type=row["type"],
        name=row["name"],
        status=ConnectorStatus(row["status"]),
        last_sync=row["last_sync"],
        created_at=row["created_at"],
    )


@router.get("/", response_model=List[ConnectorResponse])
async def list_connectors(
    tenant_id: str,
    current_user: TokenData = Depends(require_role(Role.VIEWER)),
):
    _check_tenant_scope(current_user, tenant_id)
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM connectors WHERE tenant_id = $1 ORDER BY created_at DESC", tenant_id
        )
    return [row_to_connector(r) for r in rows]


@router.post("/", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
async def create_connector(
    tenant_id: str,
    payload: ConnectorCreate,
    current_user: TokenData = Depends(require_role(Role.ADMIN)),
):
    _check_tenant_scope(current_user, tenant_id)
    pool = await get_pool()
    connector_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    import json
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO connectors (id, tenant_id, type, name, config, status, created_at)
            VALUES ($1, $2, $3, $4, $5::jsonb, 'pending', $6)
            RETURNING *
            """,
            connector_id, tenant_id, payload.type.value, payload.name,
            json.dumps(payload.config), now,
        )
    return row_to_connector(row)


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    tenant_id: str,
    connector_id: str,
    current_user: TokenData = Depends(require_role(Role.VIEWER)),
):
    _check_tenant_scope(current_user, tenant_id)
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM connectors WHERE id = $1 AND tenant_id = $2", connector_id, tenant_id
        )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connecteur introuvable.")
    return row_to_connector(row)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    tenant_id: str,
    connector_id: str,
    current_user: TokenData = Depends(require_role(Role.ADMIN)),
):
    _check_tenant_scope(current_user, tenant_id)
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM connectors WHERE id = $1 AND tenant_id = $2", connector_id, tenant_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connecteur introuvable.")


@router.post("/{connector_id}/test", response_model=ConnectorTestResult)
async def test_connector(
    tenant_id: str,
    connector_id: str,
    current_user: TokenData = Depends(require_role(Role.OPERATOR)),
):
    """
    Teste la connexion du connecteur vers la source externe.
    En P0, retourne un stub. En P1, appellera IConnector.test_connection().
    """
    _check_tenant_scope(current_user, tenant_id)
    # TODO P1 : charger le connecteur et appeler test_connection()
    return ConnectorTestResult(
        success=True,
        message="[STUB P0] Test de connexion simulé. Sera implémenté en P1.",
        latency_ms=None,
    )