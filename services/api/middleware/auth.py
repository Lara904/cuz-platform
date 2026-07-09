"""
services/api/middleware/auth.py

JWT validation + RBAC à 4 rôles.

RBAC — 4 rôles (du moins au plus privilégié) :
  viewer       → lecture seule sur son tenant
  operator     → lecture + acknowledge findings + trigger scans (son tenant)
  admin        → tout sauf suppression tenant (son tenant)
  tenant_admin → gestion globale de tous les tenants (équipe CUz platform)

En dev, un mock auth accepte username/password et génère un JWT signé avec
JWT_SECRET_KEY (défini dans .env). En prod, la validation se fait contre
Azure AD / OIDC externe.
"""
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# ── Rôles RBAC ────────────────────────────────────────────────────────────────
class Role(str, Enum):
    """
    Hiérarchie des rôles RBAC de CUz.

    viewer       → Auditeur / équipe conformité
    operator     → Analyste sécurité
    admin        → Architecte / RSSI (scope : son tenant)
    tenant_admin → Équipe CUz platform (scope : tous les tenants)
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    TENANT_ADMIN = "tenant_admin"


# Hiérarchie : un rôle supérieur hérite des droits inférieurs
ROLE_HIERARCHY: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.ADMIN: 2,
    Role.TENANT_ADMIN: 3,
}


class TokenData(BaseModel):
    sub: str  # username
    role: Role
    tenant_id: Optional[str] = None  # None pour tenant_admin (cross-tenant)
    exp: Optional[datetime] = None


# ── Génération de token (mock dev) ────────────────────────────────────────────
def create_access_token(sub: str, role: Role, tenant_id: Optional[str] = None) -> str:
    """Génère un JWT signé. Utilisé pour le mock auth en développement."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": sub,
        "role": role.value,
        "tenant_id": tenant_id,
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


# ── Validation du token ───────────────────────────────────────────────────────
async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    """Valide le JWT et retourne les données de l'utilisateur courant."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub: str = payload.get("sub")
        role_str: str = payload.get("role")
        if sub is None or role_str is None:
            raise credentials_exception
        role = Role(role_str)
        tenant_id = payload.get("tenant_id")
        return TokenData(sub=sub, role=role, tenant_id=tenant_id)
    except (JWTError, ValueError):
        raise credentials_exception


# ── Dépendances RBAC ─────────────────────────────────────────────────────────
def require_role(minimum_role: Role):
    """
    Dépendance FastAPI qui enforce un rôle minimum.

    Usage dans un router :
        @router.post("/", dependencies=[Depends(require_role(Role.TENANT_ADMIN))])
        # ou pour accéder à l'utilisateur :
        current_user = Depends(require_role(Role.ADMIN))
    """

    async def _check(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if ROLE_HIERARCHY[current_user.role] < ROLE_HIERARCHY[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rôle requis : {minimum_role.value} (vous avez : {current_user.role.value})",
            )
        return current_user

    return _check


def require_tenant_scope(tenant_id_param: str = "tenant_id"):
    """
    Dépendance qui vérifie que l'utilisateur a accès au tenant demandé.
    - tenant_admin peut accéder à tous les tenants
    - les autres rôles ne peuvent accéder qu'à leur propre tenant
    """

    async def _check(
        tenant_id: str,
        current_user: TokenData = Depends(get_current_user),
    ) -> TokenData:
        if current_user.role == Role.TENANT_ADMIN:
            return current_user  # accès global
        if current_user.tenant_id != tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé : vous n'avez pas accès à ce tenant",
            )
        return current_user

    return _check