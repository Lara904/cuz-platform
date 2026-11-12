# packages/detection/mutation_consumer.py
"""Consumer de production de la détection réactive (P2.8).

Lit cuz.graph.mutations.{tenant} en continu (publié par le GraphWriter), route chaque lot de
mutations vers les seules règles concernées (MutationRouter) et publie les nouveaux findings sur
cuz.findings.{tenant}.

Choix de fonctionnement :
- Lots : on lit un message puis ce qui arrive pendant `window_seconds` (max `max_batch`). Les règles
  s'évaluent sur tout le tenant : un rescan qui émet des milliers de mutations déclenche chaque règle
  routée UNE fois par lot, pas une fois par mutation. Latence ajoutée : `window_seconds`.
- At-least-once : l'offset n'est commité qu'après l'évaluation ET la livraison des findings. Les règles
  sont des lectures idempotentes, un rejeu ne crée pas de doublon grâce à la déduplication ci-dessous.
- Échec de règle (Neo4j indisponible...) : le lot est réessayé avec backoff. Si l'échec persiste, les
  événements du lot vont en DLQ (cuz.graph.mutations.{tenant}.dlq, reason=detection_failed:...) pour
  rejeu, puis l'offset avance : un lot qui échoue ne bloque pas la partition.
- Message illisible ou d'un autre tenant : DLQ, jamais évalué (isolation par tenant).
- Findings déjà publiés (même rule_id + mêmes nœuds) : non republiés. Cet ensemble est en mémoire : un
  redémarrage republie une fois les findings encore ouverts.
- Si la livraison des findings échoue, l'exception remonte et le process s'arrête sans commiter : les
  messages seront relus au redémarrage.

RÈGLE 1 : ce module ne lit ni n'écrit Neo4j autrement qu'en lecture via les règles Cypher.

Usage : python -m packages.detection.mutation_consumer --tenant acmecorp
"""

import logging
import os
import signal
import socket
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from confluent_kafka import Consumer, KafkaError, Producer

from packages.core.models.events import NormalizedEvent
from packages.detection.dedup import FindingKey, fingerprint
from packages.detection.models import Finding
from packages.detection.mutation_router import BatchResult, MutationRouter

logger = logging.getLogger("mutation_consumer")


def mutations_topic(tenant_id: str) -> str:
    return f"cuz.graph.mutations.{tenant_id}"


def findings_topic(tenant_id: str) -> str:
    return f"cuz.findings.{tenant_id}"


def dlq_topic(tenant_id: str) -> str:
    return f"cuz.graph.mutations.{tenant_id}.dlq"


class MutationConsumer:
    def __init__(
        self,
        tenant_id: str,
        bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        group_id: str = "cuz-detection",
        router: MutationRouter | None = None,
        consumer: Any = None,
        producer: Any = None,
        window_seconds: float = 0.2,
        max_batch: int = 500,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.tenant_id = tenant_id
        self.router = router or MutationRouter()
        self.window_seconds = window_seconds
        self.max_batch = max_batch
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self._sleep = sleep
        self._emitted: set[FindingKey] = set()
        self.stats = {"batches": 0, "events": 0, "findings": 0, "dlq": 0}
        self.consumer = consumer or Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
                # Membership statique : un redémarrage reprend sa place sans rebalancing
                "group.instance.id": os.getenv("CONSUMER_INSTANCE_ID")
                or f"cuz-detection-{socket.gethostname()}-{os.getpid()}",
                "session.timeout.ms": 10000,
            }
        )
        self.producer = producer or Producer({"bootstrap.servers": bootstrap_servers})

    # ── lecture ──────────────────────────────────────────────────────────────

    def _next_batch(self) -> list[Any] | None:
        first = self.consumer.poll(1.0)
        if first is None:
            return None
        batch = [first]
        if self.max_batch > 1:
            batch += self.consumer.consume(self.max_batch - 1, self.window_seconds)
        return batch

    def _parse(self, messages: Sequence[Any]) -> list[tuple[NormalizedEvent, bytes]]:
        """Événements valides du tenant, avec leur message brut (pour un éventuel rejeu en DLQ)."""
        events: list[tuple[NormalizedEvent, bytes]] = []
        for msg in messages:
            raw = msg.value()
            try:
                event = NormalizedEvent.model_validate_json(raw.decode())
            except Exception as exc:
                self._to_dlq(raw, f"detection_parse_error:{exc}")
                continue
            if event.tenant_id != self.tenant_id:
                self._to_dlq(raw, f"detection_tenant_mismatch:{event.tenant_id}")
                continue
            events.append((event, raw))
        return events

    # ── évaluation ───────────────────────────────────────────────────────────

    def _evaluate(self, events: list[NormalizedEvent]) -> tuple[BatchResult | None, str | None]:
        """Retourne (résultat, None) si toutes les règles ont tourné, sinon (dernier résultat
        partiel ou None, raison de l'échec) après épuisement des tentatives."""
        result: BatchResult | None = None
        reason = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                result = self.router.run_on_mutations(self.tenant_id, events)
                if not result.failed_rules:
                    return result, None
                reason = f"rules_failed:{','.join(result.failed_rules)}"
            except Exception as exc:
                reason = f"error:{exc}"
            logger.warning(
                "tenant=%s détection en échec (tentative %d/%d) : %s",
                self.tenant_id,
                attempt,
                self.max_retries,
                reason,
            )
            if attempt < self.max_retries:
                self._sleep(self.retry_backoff * 2 ** (attempt - 1))
        return result, reason

    # ── sortie ───────────────────────────────────────────────────────────────

    def _to_dlq(self, raw: bytes, reason: str) -> None:
        self.producer.produce(
            dlq_topic(self.tenant_id), value=raw, headers=[("reason", reason.encode())]
        )
        self.producer.poll(0)
        self.stats["dlq"] += 1

    def _publish(self, findings: list[Finding]) -> int:
        fresh = [f for f in findings if fingerprint(f) not in self._emitted]
        for finding in fresh:
            self.producer.produce(
                findings_topic(self.tenant_id),
                key=finding.rule_id.encode(),
                value=finding.model_dump_json().encode(),
            )
            self.producer.poll(0)
        remaining = self.producer.flush(10)
        if remaining:
            raise RuntimeError(
                f"{remaining} finding(s) non livrés sur {findings_topic(self.tenant_id)}"
            )
        self._emitted.update(fingerprint(f) for f in fresh)
        return len(fresh)

    # ── boucle ───────────────────────────────────────────────────────────────

    def process_batch(self, messages: Sequence[Any]) -> int:
        """Traite un lot et commite l'offset. Retourne le nombre de findings publiés.
        Lève si la livraison des findings échoue (offset non commité)."""
        parsed = self._parse(messages)
        events = [event for event, _ in parsed]
        published = 0
        if events:
            result, failure = self._evaluate(events)
            if result is not None:
                published = self._publish(result.findings)
            if failure is not None:
                logger.error(
                    "tenant=%s %d événement(s) en DLQ pour rejeu : %s",
                    self.tenant_id,
                    len(events),
                    failure,
                )
                for _, raw in parsed:
                    self._to_dlq(raw, f"detection_failed:{failure}")
            oldest = min(e.timestamp for e in events)
            logger.info(
                "tenant=%s lot de %d mutations, %s règle(s) lancée(s), %d finding(s) publiés, "
                "retard %.2fs",
                self.tenant_id,
                len(events),
                result.rules_run if result else 0,
                published,
                (datetime.now(UTC) - oldest).total_seconds(),
            )
        self.producer.flush(10)  # DLQ comprise : jamais d'offset commité avant
        self.consumer.commit(asynchronous=False)
        self.stats["batches"] += 1
        self.stats["events"] += len(events)
        self.stats["findings"] += published
        return published

    def run(self, idle_timeout: float | None = None, stop: threading.Event | None = None) -> None:
        """Boucle jusqu'à `stop`, ou après `idle_timeout` secondes sans message si fourni."""
        stop = stop or threading.Event()
        self.consumer.subscribe([mutations_topic(self.tenant_id)])
        idle = 0.0
        try:
            while not stop.is_set():
                batch = self._next_batch()
                if batch is None:
                    idle += 1.0
                    if idle_timeout is not None and idle >= idle_timeout:
                        break
                    continue
                idle = 0.0
                good = []
                for msg in batch:
                    err = msg.error()
                    if err is None:
                        good.append(msg)
                    elif err.code() != KafkaError._PARTITION_EOF:
                        # topic pas encore créé par le writer : on attend, on ne plante pas
                        logger.warning("tenant=%s erreur Kafka : %s", self.tenant_id, err)
                if good:
                    self.process_batch(good)
        finally:
            self.producer.flush(10)
            self.consumer.close()


def main() -> None:
    """Point d'entrée : python -m packages.detection.mutation_consumer --tenant acmecorp
    Une réplica par tenant. Arrêt propre sur SIGTERM/SIGINT."""
    import argparse

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    MutationConsumer(args.tenant).run(stop=stop)


if __name__ == "__main__":
    main()
