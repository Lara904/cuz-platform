# services/api/findings_feed.py
"""Flux des findings réactifs (P2.8) : cuz.findings.{tenant} -> store de l'API.

Le MutationConsumer publie chaque nouveau finding sur cuz.findings.{tenant}. Ce flux les lit pour
TOUS les tenants (abonnement par motif) et les passe à `on_finding` (findings.ingest_reactive).

Choix de fonctionnement :
- Un groupe par process API, offset `latest`, sans commit : chaque réplica garde son propre store en
  mémoire et doit voir tous les messages ; l'historique n'a pas à être rejoué, un premier calcul
  complet (run_all) relit le graphe.
- Isolation par tenant : le tenant du finding doit être celui du topic, sinon le message est rejeté.
- Un message illisible, un tenant incohérent ou une erreur du handler n'arrêtent jamais le flux.
- Une panne du broker ne fait pas tomber l'API : le flux journalise (au plus une fois par minute) et
  continue. Tant que le broker est coupé, l'API retombe sur le recalcul complet.
- Les topics créés après le démarrage (nouveau tenant) sont découverts en `METADATA_REFRESH_MS`.

Activation : CUZ_FINDINGS_FEED=false pour désactiver (par défaut actif).
"""

import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from confluent_kafka import Consumer, KafkaError

from packages.detection.models import Finding

logger = logging.getLogger("findings_feed")

TOPIC_PREFIX = "cuz.findings."
TOPIC_PATTERN = r"^cuz\.findings\..+"
METADATA_REFRESH_MS = 10_000
LOG_THROTTLE_SECONDS = 60.0


def feed_enabled() -> bool:
    return os.getenv("CUZ_FINDINGS_FEED", "true").strip().lower() not in ("0", "false", "no", "off")


class FindingsFeed:
    def __init__(
        self,
        on_finding: Callable[[Finding], bool],
        bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        consumer: Any = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.on_finding = on_finding
        self._clock = clock
        self._last_error_log = float("-inf")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = {"ingested": 0, "duplicates": 0, "rejected": 0, "errors": 0}
        self.consumer = consumer or Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                "group.id": f"cuz-api-findings-{socket.gethostname()}-{os.getpid()}",
                "auto.offset.reset": "latest",
                "enable.auto.commit": False,
                "topic.metadata.refresh.interval.ms": METADATA_REFRESH_MS,
            }
        )

    def handle(self, topic: str, raw: bytes) -> None:
        """Traite un message ; ne lève jamais."""
        try:
            finding = Finding.model_validate_json(raw.decode())
        except Exception as exc:
            self.stats["rejected"] += 1
            logger.warning("topic=%s message illisible ignoré : %s", topic, exc)
            return
        if topic != f"{TOPIC_PREFIX}{finding.tenant_id}":
            self.stats["rejected"] += 1
            logger.warning(
                "topic=%s finding du tenant %s rejeté : tenant incohérent avec le topic",
                topic,
                finding.tenant_id,
            )
            return
        try:
            added = self.on_finding(finding)
        except Exception:
            self.stats["errors"] += 1
            logger.exception(
                "tenant=%s ingestion du finding %s en échec", finding.tenant_id, finding.rule_id
            )
            return
        self.stats["ingested" if added else "duplicates"] += 1

    def _log_error(self, err: Any) -> None:
        now = self._clock()
        if now - self._last_error_log >= LOG_THROTTLE_SECONDS:
            self._last_error_log = now
            logger.warning("flux de findings : erreur Kafka (réessai automatique) : %s", err)

    def run(self) -> None:
        self.consumer.subscribe([TOPIC_PATTERN])
        try:
            while not self._stop.is_set():
                try:
                    msg = self.consumer.poll(1.0)
                except Exception as exc:  # défense en profondeur : le flux ne meurt pas
                    self._log_error(exc)
                    self._stop.wait(1.0)
                    continue
                if msg is None:
                    continue
                err = msg.error()
                if err is not None:
                    # aucun topic cuz.findings.* pour l'instant : normal tant qu'aucun finding n'est publié
                    if err.code() not in (
                        KafkaError._PARTITION_EOF,
                        KafkaError.UNKNOWN_TOPIC_OR_PART,
                    ):
                        self._log_error(err)
                    continue
                self.handle(msg.topic(), msg.value())
        finally:
            self.consumer.close()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self.run, name="findings-feed", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
