"""
services/api/main.py
Point d'entrée FastAPI de l'API CUz — Tenant management & Authentification (P0.8)
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from packages.audit.audit_sink import init_db as init_audit_events_db
from packages.detection.opa_client import OPAClient, OPAError
from services.api.audit import init_audit_db
from services.api.er_audit import init_er_db
from services.api.findings_feed import FindingsFeed, feed_enabled
from services.api.middleware.logging import LoggingMiddleware
from services.api.middleware.rate_limit import RateLimitMiddleware
from services.api.routers import (
    audit,
    auth,
    connectors,
    coverage,
    dashboard,
    dora_compliance,
    entity_resolution,
    exports,
    findings,
    graph,
    health,
    tenant_onboarding,
    tenants,
    webhooks,
)
from services.api.routers.connectors import init_db as init_connectors_db
from services.api.routers.tenants import init_db as init_tenants_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise les ressources au démarrage et les libère à l'arrêt."""
    # Startup : vérifier que PostgreSQL et Redis sont accessibles
    print("CUz API démarrage...")
    await init_tenants_db()
    await init_connectors_db()
    await init_audit_db()
    await init_er_db()
    await (
        init_audit_events_db()
    )  # P2.12 : table audit_events (JIT/remédiation), distincte de finding_audit
    # Policies OPA : chargées dès le démarrage, et revérifiées avant chaque évaluation (auto-réparation).
    # Un échec ici n'empêche pas l'API de démarrer, il est journalisé et signalé par detection_errors.
    try:
        reloaded = await run_in_threadpool(OPAClient().ensure_policies)
        logging.getLogger(__name__).info(
            "OPA : policies à jour (rechargées : %s)", reloaded or "aucune"
        )
    except OPAError as e:
        logging.getLogger(__name__).error("OPA : policies non garanties au démarrage : %s", e)
    # Findings réactifs (P2.8) : un échec d'abonnement ne doit jamais empêcher l'API de démarrer,
    # elle retombe alors sur le recalcul complet (run_all)
    feed: FindingsFeed | None = None
    if feed_enabled():
        try:
            feed = FindingsFeed(findings.ingest_reactive)
            feed.start()
        except Exception:
            logging.getLogger(__name__).exception("flux de findings réactifs non démarré")
            feed = None
    yield
    # Shutdown
    if feed is not None:
        feed.stop()
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
app.include_router(tenant_onboarding.router)
app.include_router(connectors.router)
app.include_router(findings.router)
app.include_router(dashboard.router)
app.include_router(graph.router)
app.include_router(exports.router)
app.include_router(coverage.router)
app.include_router(entity_resolution.router)
app.include_router(webhooks.router)
app.include_router(audit.router)
app.include_router(dora_compliance.router)


@app.get("/", tags=["root"])
async def root():
    return {"service": "cuz-api", "version": "0.1.0", "status": "ok"}
