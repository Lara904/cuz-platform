"""
services/api/routers/tenants.py

CRUD tenants — endpoints principaux de P0.8.

Endpoints :
  GET    /api/v1/tenants              → Lister (tenant_admin only)
  POST   /api/v1/tenants              → Créer un tenant (tenant_admin only)
  GET    /api/v1/tenants/{tenant_id}  → Détail (admin+ ou propriétaire)
  PUT    /api/v1/tenants/{tenant_id}  → Mettre à jour (admin+)
  DELETE /api/v1/tenants/{tenant_id}  → Supprimer (tenant_admin only)

En P0, le stockage est PostgreSQL via SQLAlchemy async.
Le provisioning automatique (contrainte Neo4j, topic Kafka) est prévu
mais implémenté en stub pour P0.8 — il sera complété en P1.
"""
import os
from datetime import datetime, timezone
from typing import List

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from services.api.middleware.auth import Role, TokenData, require_role
from services.api.models.tenant import TenantCreate, TenantResponse, TenantStatus, TenantUpdate

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cuz:cuzpassword@localhost:5432/cuzdb")

# ── Connexion PostgreSQL ──────────────────────────────────────────────────────
_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    return _pool


# ── Initialisation du schéma ──────────────────────────────────────────────────
async def init_db():
    """Crée la table tenants si elle n'existe pas."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                status      TEXT NOT NULL DEFAULT 'active',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


# ── Helpers ───────────────────────────────────────────────────────────────────
def row_to_tenant(row: asyncpg.Record) -> TenantResponse:
    return TenantResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        status=TenantStatus(row["status"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def _provision_tenant(tenant_id: str):
    """
    Stub de provisioning automatique — sera complété en P1 :
    - Contrainte Neo4j : CREATE CONSTRAINT FOR (n:Node) REQUIRE n.tenant_id IS NOT NULL
    - Topic Redpanda : cuz.raw.{tenant_id}
    - Entrée audit trail PostgreSQL
    """
    print(f"[STUB] Provisioning tenant : {tenant_id}")
    # TODO P1 : appeler Neo4j driver et Kafka admin client


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[TenantResponse])
async def list_tenants(
    current_user: TokenData = Depends(require_role(Role.TENANT_ADMIN)),
):
    """Liste tous les tenants. Réservé au rôle tenant_admin."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM tenants ORDER BY created_at DESC")
    return [row_to_tenant(r) for r in rows]


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreate,
    current_user: TokenData = Depends(require_role(Role.TENANT_ADMIN)),
):
    """
    Crée un nouveau tenant.
    Provisionne automatiquement :
    - La contrainte Neo4j pour le tenant_id
    - Le topic Redpanda cuz.raw.{tenant_id}
    - L'entrée PostgreSQL pour l'audit trail
    """
    pool = await get_pool()
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1", payload.id)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Le tenant '{payload.id}' existe déjà.",
            )
        row = await conn.fetchrow(
            """
            INSERT INTO tenants (id, name, description, status, created_at, updated_at)
            VALUES ($1, $2, $3, 'active', $4, $4)
            RETURNING *
            """,
            payload.id, payload.name, payload.description, now,
        )

    await _provision_tenant(payload.id)
    return row_to_tenant(row)


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    current_user: TokenData = Depends(require_role(Role.VIEWER)),
):
    """
    Détail d'un tenant.
    - tenant_admin : peut voir tous les tenants
    - autres rôles : uniquement leur propre tenant
    """
    # Vérification du scope tenant (non-admin ne voit que son tenant)
    if current_user.role != Role.TENANT_ADMIN and current_user.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé.")

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM tenants WHERE id = $1", tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' introuvable.")
    return row_to_tenant(row)


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    payload: TenantUpdate,
    current_user: TokenData = Depends(require_role(Role.ADMIN)),
):
    """Mise à jour d'un tenant. Rôle minimum : admin."""
    if current_user.role != Role.TENANT_ADMIN and current_user.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé.")

    pool = await get_pool()
    now = datetime.now(timezone.utc)

    updates = {}
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.description is not None:
        updates["description"] = payload.description
    if payload.status is not None:
        updates["status"] = payload.status.value

    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Aucun champ à mettre à jour.")

    set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(updates.keys()))
    values = [tenant_id] + list(updates.values()) + [now]
    query = f"""
        UPDATE tenants
        SET {set_clause}, updated_at = ${len(values)}
        WHERE id = $1
        RETURNING *
    """

    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, *values)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' introuvable.")
    return row_to_tenant(row)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: str,
    current_user: TokenData = Depends(require_role(Role.TENANT_ADMIN)),
):
    """
    Supprime un tenant. Réservé au rôle tenant_admin.
    ATTENTION : opération irréversible. Supprime toutes les données associées.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_id)
    if result == "DELETE 0":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' introuvable.")
    print(f"[STUB] Déprovision tenant : {tenant_id}")
    # TODO P1 : purger Neo4j, topics Kafka, etc.