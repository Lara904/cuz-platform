"""
services/api/routers/auth.py

Authentification mock pour le développement.
En production, remplacer par la validation OIDC Azure AD.

Endpoint : POST /auth/token
  → Accepte username + password + role (form data)
  → Retourne un JWT signé

NOTE SÉCURITÉ : Ce mock n'est JAMAIS déployé en production.
En prod, les tokens sont émis par Azure AD et validés via JWKS.
"""
import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from services.api.middleware.auth import Role, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

# Utilisateurs de dev fictifs (username → (password, role, tenant_id))
DEV_USERS: dict[str, tuple[str, Role, str | None]] = {
    "viewer_user": ("dev", Role.VIEWER, "stellantis-financial"),
    "operator_user": ("dev", Role.OPERATOR, "stellantis-financial"),
    "admin_user": ("dev", Role.ADMIN, "stellantis-financial"),
    "admin": ("dev", Role.TENANT_ADMIN, None),  # tenant_admin = cross-tenant
}

IS_DEV = os.getenv("ENV", "development") == "development"


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    tenant_id: str | None


@router.post("/token", response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Génère un token JWT (mock dev uniquement).

    Utilisateurs disponibles :
    - admin / dev → tenant_admin (accès global)
    - admin_user / dev → admin (stellantis-financial)
    - operator_user / dev → operator (stellantis-financial)
    - viewer_user / dev → viewer (stellantis-financial)
    """
    if not IS_DEV:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint non disponible en production. Utilisez Azure AD.",
        )

    user = DEV_USERS.get(form_data.username)
    if not user or user[0] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _, role, tenant_id = user
    token = create_access_token(sub=form_data.username, role=role, tenant_id=tenant_id)

    return Token(
        access_token=token,
        token_type="bearer",
        role=role.value,
        tenant_id=tenant_id,
    )