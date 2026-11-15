"""
Trace précise, message par message, de PipelineConsumer.process() sur un lot FRAIS et
ISOLÉ de RawEvents Terraform (republiés exprès par ce script), avec un group_id Kafka
jetable — pour éliminer toute interférence avec l'historique du groupe "cuz-ingestion"
ou le bruit de fond des CronJobs.

Usage :
    python scripts/trace_pipeline_consumer.py
"""

import asyncio
import json
import logging
import os

from confluent_kafka import TopicPartition
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from packages.connectors.terraform.connector import TerraformConnector  # noqa: E402
from packages.ingestion.consumer import PipelineConsumer  # noqa: E402
from packages.ingestion.producer import EventProducer  # noqa: E402

TENANT = "acmecorp"
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


def main() -> None:
    topic = f"cuz.raw.{TENANT}"

    # Group jetable : on se positionne explicitement à LA FIN de chaque partition avant de
    # republier, pour ne lire QUE le lot frais (pas les milliers de messages historiques :
    # "auto.offset.reset: earliest" sinon tout relire depuis le début du topic).
    consumer = PipelineConsumer(bootstrap_servers=BOOTSTRAP, group_id=f"trace-{os.getpid()}")
    metadata = consumer.consumer.list_topics(topic, timeout=10)
    partitions = list(metadata.topics[topic].partitions.keys())
    ends = []
    for p in partitions:
        _low, high = consumer.consumer.get_watermark_offsets(
            TopicPartition(topic, p), timeout=10, cached=False
        )
        ends.append(TopicPartition(topic, p, high))
    consumer.consumer.assign(ends)

    connector = TerraformConnector(tenant_id=TENANT, config={})
    raw_events = asyncio.run(connector.pull_full())
    logger.info("%d RawEvents Terraform à republier", len(raw_events))
    by_event_id = {e.event_id: e.raw_data["resource"] for e in raw_events}

    producer = EventProducer(BOOTSTRAP)
    for raw in raw_events:
        producer.publish(raw)
    producer.flush()
    logger.info("Republiés sur cuz.raw.%s", TENANT)

    seen: dict[str, str] = {}

    def on_normalized(event):  # noqa: ANN001
        node = event.node
        label = node.name if node else "(arête, pas de nœud)"
        logger.info(
            "  -> NormalizedEvent émis pour raw_event_id=%s : %s", event.raw_event_id, label
        )

    idle = 0.0
    try:
        while idle < 15.0:
            msg = consumer.consumer.poll(1.0)
            if msg is None:
                idle += 1.0
                continue
            idle = 0.0
            if msg.error():
                continue
            raw_bytes = msg.value()
            result = consumer.process(TENANT, raw_bytes, on_normalized=on_normalized)
            # on ne trace que les messages de CE lot (pas le bruit de fond d'autres connecteurs)
            try:
                payload = json.loads(raw_bytes.decode())
                eid = payload.get("event_id")
            except Exception:
                eid = None
            if eid in by_event_id:
                resource = by_event_id[eid]
                logger.info(
                    "process() -> %-16s type=%s name=%s",
                    result,
                    resource["type"],
                    resource["name"],
                )
                seen[eid] = result
            consumer.consumer.commit(message=msg)
    finally:
        consumer.normalized_producer.flush(timeout=10)
        consumer.dlq_producer.flush(timeout=10)
        consumer.consumer.close()

    logger.info("Bilan : %d/%d messages de ce lot vus par process()", len(seen), len(raw_events))
    missing = [r["type"] + "." + r["name"] for eid, r in by_event_id.items() if eid not in seen]
    if missing:
        logger.warning("JAMAIS VUS par le consumer : %s", missing)


if __name__ == "__main__":
    main()
