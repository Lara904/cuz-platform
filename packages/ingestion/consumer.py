# packages/ingestion/consumer.py
import logging
import os
import socket

from confluent_kafka import Consumer, KafkaError, Producer

from packages.core.models.events import NormalizedEvent, RawEvent
from packages.ingestion.normalizer import Normalizer

logger = logging.getLogger(__name__)
SEEN_EVENT_IDS: set = set()  # en mémoire — Redis en prod


class PipelineConsumer:
    def __init__(
        self,
        bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092"),
        group_id: str = "cuz-ingestion",
        max_retries: int = 3,
    ):
        self.normalizer = Normalizer()
        self.max_retries = max_retries
        self.consumer = Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
                "group.instance.id": os.getenv("CONSUMER_INSTANCE_ID") or f"cuz-ingestion-{socket.gethostname()}-{os.getpid()}",
                "session.timeout.ms": 10000,
            }
        )
        self.dlq_producer = Producer({"bootstrap.servers": bootstrap_servers})
        self.normalized_producer = Producer({"bootstrap.servers": bootstrap_servers})

    def _get_dlq_topic(self, tenant_id: str) -> str:
        return f"cuz.graph.mutations.{tenant_id}.dlq"

    def _get_normalized_topic(self, tenant_id: str) -> str:
        return f"cuz.normalized.{tenant_id}"

    def _to_dlq(self, tenant_id: str, raw_bytes: bytes, reason: str) -> None:
        topic = self._get_dlq_topic(tenant_id)
        self.dlq_producer.produce(topic, value=raw_bytes, headers=[("reason", reason.encode())])
        self.dlq_producer.poll(0)

    def _publish_normalized(self, tenant_id: str, event: NormalizedEvent) -> None:
        """Sortie par défaut : le GraphWriter consomme cuz.normalized.{tenant_id}."""
        self.normalized_producer.produce(
            topic=self._get_normalized_topic(tenant_id),
            key=event.event_id.encode(),
            value=event.model_dump_json().encode(),
        )
        self.normalized_producer.poll(0)

    def process(self, tenant_id: str, raw_bytes: bytes, on_normalized=None) -> str:
        """Traite un message brut. Retourne 'duplicate', 'parse_error',
        'normalize_error' ou 'processed'. Ne lit ni ne commit Kafka."""
        try:
            raw = RawEvent.model_validate_json(raw_bytes.decode())
        except Exception as e:
            self._to_dlq(tenant_id, raw_bytes, f"parse_error:{e}")
            return "parse_error"

        # Idempotence
        if raw.event_id in SEEN_EVENT_IDS:
            return "duplicate"
        SEEN_EVENT_IDS.add(raw.event_id)

        emit = on_normalized or (lambda ev: self._publish_normalized(tenant_id, ev))
        retries = 0
        while retries < self.max_retries:
            try:
                # normalize() retourne une LISTE (nœuds ET arêtes)
                for normalized in self.normalizer.normalize(raw):
                    emit(normalized)
                return "processed"
            except Exception as e:
                retries += 1
                if retries >= self.max_retries:
                    self._to_dlq(tenant_id, raw_bytes, f"normalize_error:{e}")
                    return "normalize_error"
        return "normalize_error"  # max_retries <= 0

    def run(self, tenant_id: str, on_normalized=None, idle_timeout: float | None = None) -> None:
        """Si idle_timeout (s) est fourni, s'arrête après autant de secondes sans message."""
        topic = f"cuz.raw.{tenant_id}"
        self.consumer.subscribe([topic])
        idle = 0.0
        try:
            while True:
                msg = self.consumer.poll(1.0)
                if msg is None:
                    idle += 1.0
                    if idle_timeout is not None and idle >= idle_timeout:
                        break
                    continue
                idle = 0.0
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                self.process(tenant_id, msg.value(), on_normalized)
                self.consumer.commit(message=msg)
        finally:
            self.normalized_producer.flush(timeout=10)  # ne rien perdre en sortie
            self.dlq_producer.flush(timeout=10)
            self.consumer.close()


def main() -> None:
    """Point d'entrée Deployment : python -m packages.ingestion.consumer --tenant acmecorp"""
    import argparse

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    PipelineConsumer().run(args.tenant)


if __name__ == "__main__":
    main()
