"""
Scan AcmeCorp via le pipeline complet, conforme à la règle 1 (aucune écriture
directe dans Neo4j) :

    connecteurs → Redpanda cuz.raw.{tenant}
                → PipelineConsumer (normalisation) → cuz.normalized.{tenant}
                → GraphWriter (upsert Neo4j + OWNS)

Usage :
    python scripts/run_scan.py [--idle-timeout 30]

Variables d'environnement (depuis .env) :
    KAFKA_BOOTSTRAP_SERVERS (défaut localhost:9092)
    MINIO_ENDPOINT, MINIO_USER, MINIO_PASSWORD
    GITEA_URL, GITEA_ADMIN_TOKEN
    ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
    SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
"""
import argparse
import asyncio
import logging
import os

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from packages.graph.client import Neo4jClient  # noqa: E402
from packages.graph.writer import GraphWriter  # noqa: E402
from packages.ingestion.consumer import PipelineConsumer  # noqa: E402
from packages.ingestion.producer import EventProducer  # noqa: E402
from packages.ingestion.sources import build_connectors  # noqa: E402

TENANT = "acmecorp"
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


async def publish_raw(connectors: dict) -> int:
    """Étape 1 : chaque connecteur publie ses RawEvents sur cuz.raw.{tenant}."""
    producer = EventProducer(BOOTSTRAP)
    total = 0
    for name, connector in connectors.items():
        try:
            raw_events = await connector.pull_full()
        except Exception as e:
            logger.warning("[%s] pull_full() échoué : %s", name, e)
            continue
        for raw in raw_events:
            producer.publish(raw)
        logger.info("[%s] %d RawEvents publiés", name, len(raw_events))
        total += len(raw_events)
    producer.flush()
    return total


def summarize() -> None:
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        nodes = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) RETURN count(n) AS c", t=TENANT
        ).single()["c"]
        edges = {r["et"]: r["c"] for r in session.run(
            "MATCH ()-[r:CUZ_EDGE {tenant_id: $t}]->() "
            "RETURN r.edge_type AS et, count(r) AS c", t=TENANT)}
    logger.info("Nœuds (%s) : %d", TENANT, nodes)
    logger.info("Arêtes : %s", edges)
    if nodes > 200:
        logger.info("✅ Critère P1.7 : > 200 nœuds — OK")
    else:
        logger.warning("⚠️  Critère P1.7 : %d nœuds (attendu > 200)", nodes)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--idle-timeout", type=float, default=30.0,
                        help="secondes sans message avant l'arrêt des consumers")
    args = parser.parse_args()

    connectors = build_connectors()
    logger.info("Connecteurs actifs : %s", ", ".join(connectors) or "aucun")
    published = asyncio.run(publish_raw(connectors))
    logger.info("Total RawEvents publiés : %d", published)

    # Étapes 2 et 3 : consumers qui s'arrêtent après idle_timeout secondes sans message
    PipelineConsumer(bootstrap_servers=BOOTSTRAP).run(TENANT, idle_timeout=args.idle_timeout)
    GraphWriter(bootstrap_servers=BOOTSTRAP).run(TENANT, idle_timeout=args.idle_timeout)

    summarize()


if __name__ == "__main__":
    main()
