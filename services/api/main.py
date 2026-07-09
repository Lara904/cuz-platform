"""
services/api/main.py
Point d'entrée FastAPI de l'API CUz — Tenant management & Authentification (P0.8)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from services.api.middleware.logging import LoggingMiddleware
from services.api.middleware.rate_limit import RateLimitMiddleware
from services.api.routers import auth, connectors, health, tenants


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise les ressources au démarrage et les libère à l'arrêt."""
    # Startup : vérifier que PostgreSQL et Redis sont accessibles
    print("CUz API démarrage...")
    yield
    # Shutdown
    print("CUz API arrêt.")


app = FastAPI(
    title="CUz Platform API",
    description="API de gestion des tenants et de l'authentification — CUz Unified SI Intelligence",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restreindre en production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(tenants.router)
app.include_router(connectors.router)


@app.get("/", tags=["root"])
async def root():
    return {"service": "cuz-api", "version": "0.1.0", "status": "ok"}