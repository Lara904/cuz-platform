# services/api/routers/webhooks.py
"""
Webhooks Gitea (P2.7) : push sur la branche par défaut -> RawEvent « repository » sur cuz.raw.{tenant}.

Authentification par signature HMAC, pas par JWT. ÉCHEC FERMÉ : sans GITEA_WEBHOOK_SECRET l'endpoint
refuse tout (503) ; accepter des événements non signés laisserait n'importe qui écrire dans le pipeline.
Le webhook ne publie que sur Redpanda (RÈGLE 1) : le graphe n'est jamais écrit d'ici.

Le RawEvent publié a exactement la forme de GiteaConnector.pull_full() (dépendances relues dans le
dépôt), donc le normalizer existant le traite sans cas particulier. Son timestamp est l'instant de
réception du webhook : c'est l'origine de la latence d'ingestion mesurée.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from packages.connectors.gitea.connector import GiteaConnector
from packages.ingestion.producer import EventProducer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

MAX_BODY_BYTES = 1_048_576
_producer: EventProducer | None = None


def _get_producer() -> EventProducer:
    global _producer
    if (
        _producer is None
    ):  # créé à l'usage : l'import de l'API ne doit pas ouvrir de connexion Kafka
        _producer = EventProducer()
    return _producer


def _connector(tenant_id: str) -> GiteaConnector:
    return GiteaConnector(
        tenant_id,
        os.getenv("GITEA_URL", "http://localhost:3000"),
        os.getenv("GITEA_ADMIN_TOKEN", ""),
        org=os.getenv("GITEA_ORG", "acmecorp"),
    )


def _signature_valid(body: bytes, secret: str, headers) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    candidates = [
        headers.get("X-Gitea-Signature", ""),
        headers.get("X-Hub-Signature-256", "").removeprefix("sha256="),
    ]
    return any(hmac.compare_digest(expected, c) for c in candidates if c)


def _publish(event) -> None:
    producer = _get_producer()
    producer.publish(event)
    producer.flush()


@router.post("/gitea")
async def gitea_webhook(request: Request):
    secret = os.getenv("GITEA_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(
            status_code=503, detail="Webhook non configuré (GITEA_WEBHOOK_SECRET absent)"
        )
    received_at = datetime.now(UTC)
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload trop volumineux")
    if not _signature_valid(body, secret, request.headers):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        payload = json.loads(body)
        repo = payload["repository"]
        owner, name = repo["owner"]["login"], repo["name"]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Payload Gitea invalide") from None

    kind = request.headers.get("X-Gitea-Event", "")
    default_ref = f"refs/heads/{repo.get('default_branch', 'main')}"
    if kind != "push" or payload.get("ref") != default_ref:
        # create/delete/pull_request et pushs sur d'autres branches ne changent pas les dépendances du graphe
        return {
            "status": "ignored",
            "reason": f"{kind or 'événement inconnu'} sans effet sur le graphe",
        }

    tenant_id = os.getenv(
        "CUZ_WEBHOOK_TENANT", "acmecorp"
    )  # résolu par org/repo en multi-tenant (P2.14)
    try:
        event = await _connector(tenant_id).pull_repo(owner, name)
    except httpx.HTTPError as e:
        logger.error(
            "webhook gitea tenant=%s repo=%s/%s : lecture Gitea impossible : %s",
            tenant_id,
            owner,
            name,
            e,
        )
        raise HTTPException(status_code=502, detail="Gitea injoignable") from None
    if event is None:
        return {"status": "ignored", "reason": "dépôt introuvable"}
    event.timestamp = received_at
    await run_in_threadpool(_publish, event)
    logger.info(
        "webhook gitea tenant=%s repo=%s/%s event=%s", tenant_id, owner, name, event.event_id
    )
    return {"status": "accepted", "event_id": event.event_id}
