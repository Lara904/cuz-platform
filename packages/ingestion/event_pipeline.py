# packages/ingestion/event_pipeline.py
"""Pipeline événementiel (P2.7) : démarre en parallèle les flux subscribe_events() des connecteurs
temps réel (Kubernetes watch, détection cloud) et publie leurs RawEvents sur cuz.raw.{tenant}.

Gitea n'a pas de tâche ici : ses événements arrivent par le webhook (services/api/routers/webhooks.py),
déjà publié sur Redpanda. La réconciliation périodique (P1.14) continue de tourner en parallèle :
c'est le filet de sécurité quand un flux temps réel est coupé.

RÈGLE 1 : ce module ne publie que sur Redpanda, jamais dans Neo4j.

Un flux qui plante est relancé avec un backoff exponentiel SANS toucher aux autres : un watch Kubernetes
coupé ne doit pas arrêter la détection cloud.

Latence : `measure_p95_latency()` mesure le délai connecteur -> bus (timestamp du RawEvent -> publication).
La latence d'ingestion de bout en bout (réception -> nœud visible dans Neo4j) se mesure avec
scripts/measure_ingest_latency.py.

Usage : python -m packages.ingestion.event_pipeline --tenant acmecorp
"""
import argparse
import asyncio
import logging
import math
import sys
from collections import defaultdict
from datetime import UTC, datetime

from packages.core.models.events import RawEvent
from packages.ingestion.producer import EventProducer

logger = logging.getLogger("event_pipeline")

EVENT_SOURCES = ("kubernetes", "cloud_detection")  # gitea : webhook


class EventPipeline:
    def __init__(self, connectors: dict, producer: EventProducer | None = None,
                 backoff_seconds: float = 5.0, max_backoff_seconds: float = 60.0):
        """connectors : {"kubernetes": KubernetesConnector(...), "cloud_detection": ...}"""
        self.connectors = connectors
        self.producer = producer or EventProducer()
        self.backoff_seconds = backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.published: dict[str, int] = defaultdict(int)
        self.restarts: dict[str, int] = defaultdict(int)
        self._latencies: dict[str, list[float]] = defaultdict(list)

    async def _run_connector_stream(self, name: str, connector) -> None:
        """Consomme UN flux jusqu'à sa fin ou son erreur."""
        async for raw_event in connector.subscribe_events():
            self._publish(name, raw_event)

    def _publish(self, name: str, raw_event: RawEvent) -> None:
        self.producer.publish(raw_event)
        self._latencies[name].append((datetime.now(UTC) - raw_event.timestamp).total_seconds())
        self.published[name] += 1
        logger.info("event_pipeline: %s -> cuz.raw.%s event=%s", name, raw_event.tenant_id,
                    raw_event.event_id)

    async def _supervise(self, name: str, connector) -> None:
        backoff = self.backoff_seconds
        while True:
            try:
                await self._run_connector_stream(name, connector)
                logger.warning("event_pipeline: flux %s terminé, relance", name)
                backoff = self.backoff_seconds
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.restarts[name] += 1
                logger.error("event_pipeline: flux %s en erreur (%s), relance dans %.1fs", name, e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.max_backoff_seconds)

    async def run(self) -> None:
        tasks = [asyncio.create_task(self._supervise(name, conn), name=f"stream-{name}")
                 for name, conn in self.connectors.items()]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.producer.flush()  # ne rien perdre à l'arrêt

    def measure_p95_latency(self, name: str | None = None) -> float:
        """P95 (rang inférieur) du délai connecteur -> bus, pour un flux ou pour tous."""
        samples = sorted(self._latencies[name] if name else
                         [v for values in self._latencies.values() for v in values])
        if not samples:
            return 0.0
        return samples[max(math.ceil(0.95 * len(samples)) - 1, 0)]


def main() -> int:
    import os

    from dotenv import load_dotenv

    from packages.ingestion.sources import build_connectors

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    connectors = {n: c for n, c in build_connectors(args.tenant).items() if n in EVENT_SOURCES}
    if not connectors:
        logger.error("aucun connecteur temps réel actif (%s)", ", ".join(EVENT_SOURCES))
        return 1
    logger.info("flux temps réel : %s", ", ".join(connectors))
    pipeline = EventPipeline(connectors, EventProducer(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092")))
    try:
        asyncio.run(pipeline.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
