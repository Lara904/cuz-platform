"""
services/api/routers/health.py
Health check endpoint — pas d'auth requise.
Retourne 200 si l'API tourne, indépendamment des services externes.
"""
from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    """Vérifie que l'API répond. Utilisé par Docker et les load balancers."""
    return {
        "status": "ok",
        "service": "cuz-api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }