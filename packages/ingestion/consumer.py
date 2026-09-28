# packages/ingestion/consumer.py
import json
import logging
from confluent_kafka import Consumer, KafkaError, Producer
from packages.core.models.events import RawEvent
from packages.ingestion.normalizer import Normalizer

logger = logging.getLogger(__name__)
SEEN_EVENT_IDS: set = set()  # en mémoire — Redis en prod

class PipelineConsumer:
    def __init__(
        self,
        bootstrap_servers: str = "localhost:19092",
        group_id: str = "cuz-ingestion",
        max_retries: int = 3,
    ):
        self.normalizer = Normalizer()
        self.max_retries = max_retries
        self.consumer = Consumer({
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.dlq_producer = Producer({"bootstrap.servers": bootstrap_servers})

    def _get_dlq_topic(self, tenant_id: str) -> str:
        return f"cuz.graph.mutations.{tenant_id}.dlq"

    def _to_dlq(self, tenant_id: str, raw_bytes: bytes, reason: str) -> None:
        topic = self._get_dlq_topic(tenant_id)
        self.dlq_producer.produce(topic, value=raw_bytes,
                                   headers=[("reason", reason.encode())])
        self.dlq_producer.poll(0)

    def run(self, tenant_id: str, on_normalized=None) -> None:
        topic = f"cuz.raw.{tenant_id}"
        self.consumer.subscribe([topic])
        try:
            while True:
                msg = self.consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                raw_bytes = msg.value()
                try:
                    raw = RawEvent.model_validate_json(raw_bytes.decode())
                except Exception as e:
                    self._to_dlq(tenant_id, raw_bytes, f"parse_error:{e}")
                    self.consumer.commit(message=msg)
                    continue
                # Idempotence
                if raw.event_id in SEEN_EVENT_IDS:
                    self.consumer.commit(message=msg)
                    continue
                SEEN_EVENT_IDS.add(raw.event_id)
                retries = 0
                while retries < self.max_retries:
                    try:
                        # V3 : normalize() retourne une LISTE, on itère dessus
                        # (v1.0 testait `if normalized`, ne s'applique plus)
                        normalized_list = self.normalizer.normalize(raw)
                        if on_normalized:
                            for normalized in normalized_list:
                                on_normalized(normalized)
                        break
                    except Exception as e:
                        retries += 1
                        if retries >= self.max_retries:
                            self._to_dlq(tenant_id, raw_bytes, f"normalize_error:{e}")
                self.consumer.commit(message=msg)
        finally:
            self.consumer.close()