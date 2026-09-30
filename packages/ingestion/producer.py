# packages/ingestion/producer.py
from confluent_kafka import Producer

from packages.core.models.events import RawEvent


class EventProducer:
    def __init__(self, bootstrap_servers: str = "localhost:19092"):
        self.producer = Producer({"bootstrap.servers": bootstrap_servers})

    def _get_topic(self, tenant_id: str) -> str:
        return f"cuz.raw.{tenant_id}"

    def publish(self, event: RawEvent) -> None:
        topic = self._get_topic(event.tenant_id)
        payload = event.model_dump_json().encode("utf-8")
        self.producer.produce(
            topic=topic,
            key=event.event_id.encode("utf-8"),
            value=payload,
        )
        self.producer.poll(0)

    def flush(self) -> None:
        self.producer.flush(timeout=10)
