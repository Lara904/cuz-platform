"""
Variante de debug_kafka_tail.py : cherche depuis un INSTANT donné (pas les N derniers
messages), pour ne pas être noyé par le bruit de fond des CronJobs (freshness-decay,
reconcile-*) qui publient en continu sur cuz.normalized.{tenant}.

Usage :
    python scripts/debug_kafka_since.py cuz.normalized.acmecorp --since-minutes 180 \
        --needle '"source":"terraform"' --cap 200000
"""

import argparse
import os
import time

from confluent_kafka import Consumer, TopicPartition
from dotenv import load_dotenv

load_dotenv()
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


def consume_since(topic: str, since_minutes: float, needle: str, cap: int) -> tuple[int, list[str]]:
    consumer = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": f"debug-since-{os.getpid()}",
            "enable.auto.commit": False,
        }
    )
    metadata = consumer.list_topics(topic, timeout=10)
    if topic not in metadata.topics or metadata.topics[topic].error is not None:
        print(f"Topic introuvable : {topic}")
        consumer.close()
        return 0, []
    partitions = list(metadata.topics[topic].partitions.keys())

    since_ms = int((time.time() - since_minutes * 60) * 1000)
    search_tps = [TopicPartition(topic, p, since_ms) for p in partitions]
    resolved = consumer.offsets_for_times(search_tps, timeout=10)

    assignments = []
    ends: dict[int, int] = {}
    for tp in resolved:
        low, high = consumer.get_watermark_offsets(
            TopicPartition(topic, tp.partition), timeout=10, cached=False
        )
        ends[tp.partition] = high
        offset = tp.offset if tp.offset is not None and tp.offset >= 0 else low
        assignments.append(TopicPartition(topic, tp.partition, offset))
    consumer.assign(assignments)

    read = 0
    hits: list[str] = []
    remaining = {a.partition: ends[a.partition] - a.offset for a in assignments}
    while any(v > 0 for v in remaining.values()) and read < cap:
        msg = consumer.poll(2.0)
        if msg is None:
            break
        if msg.error():
            continue
        read += 1
        text = msg.value().decode("utf-8", errors="replace")
        if needle in text:
            hits.append(text[:400])
        remaining[msg.partition()] = ends[msg.partition()] - (msg.offset() + 1)
    consumer.close()
    return read, hits


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("topic")
    parser.add_argument("--since-minutes", type=float, default=180.0)
    parser.add_argument("--needle", default='"source":"terraform"')
    parser.add_argument("--cap", type=int, default=200_000, help="messages max lus par partition")
    args = parser.parse_args()

    read, hits = consume_since(args.topic, args.since_minutes, args.needle, args.cap)
    print(f"{read} message(s) scannés sur {args.topic} depuis {args.since_minutes} min")
    print(f"{len(hits)} message(s) contenant {args.needle!r}")
    for h in hits[:20]:
        print("HIT ->", h)


if __name__ == "__main__":
    main()
