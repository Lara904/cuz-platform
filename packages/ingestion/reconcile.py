# packages/ingestion/reconcile.py
"""Réconciliation périodique d'une source (CronJobs P1.14).

Usage : python -m packages.ingestion.reconcile --source servicenow --tenant acmecorp

Scan complet du connecteur → RawEvents publiés sur cuz.raw.{tenant} (règle 1 : jamais
d'écriture directe dans Neo4j). Succès ou échec est enregistré dans connector_status.
"""
import argparse
import asyncio
import logging
import sys

from dotenv import load_dotenv

from packages.ingestion import status
from packages.ingestion.producer import EventProducer
from packages.ingestion.sources import build_connectors

load_dotenv()
logger = logging.getLogger("reconcile")

# Nom de source des CronJobs → clé de build_connectors()
SOURCE_KEYS = {"servicenow": "servicenow", "entra_id": "entra_id", "gitea": "gitea",
               "minio": "minio", "terraform": "terraform"}


async def reconcile(source: str, tenant_id: str) -> int:
    """Retourne le nombre de RawEvents publiés. Lève une exception en cas d'échec."""
    connector = build_connectors(tenant_id).get(SOURCE_KEYS[source])
    if connector is None:
        raise RuntimeError(f"connecteur '{source}' non configuré")
    await connector.test_connection()
    events = await connector.pull_full()
    producer = EventProducer()
    for raw in events:
        producer.publish(raw)
    producer.flush()
    return len(events)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, choices=sorted(SOURCE_KEYS))
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        count = asyncio.run(reconcile(args.source, args.tenant))
    except Exception as e:  # on enregistre l'échec, sans supprimer aucun nœud
        logger.error("réconciliation %s échouée : %s", args.source, e)
        asyncio.run(status.init_status_db())
        asyncio.run(status.mark_failure(args.tenant, args.source, str(e)))
        return 1
    asyncio.run(status.init_status_db())
    asyncio.run(status.mark_success(args.tenant, args.source))
    logger.info("réconciliation %s : %d RawEvents publiés", args.source, count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
