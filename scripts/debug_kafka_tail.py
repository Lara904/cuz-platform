"""
Diagnostic bas niveau : lit directement les N derniers messages d'un topic via
confluent_kafka (la MÊME librairie que PipelineConsumer/GraphWriter), sans passer par
`rpk topic consume` — pour éliminer un éventuel artefact d'affichage/troncature de rpk
avant de conclure à un vrai bug dans le code du pipeline.

Usage :
    python scripts/debug_kafka_tail.py cuz.raw.acmecorp -n 100
    python scripts/debug_kafka_tail.py cuz.normalized.acmecorp -n 400
"""

import argparse
import os

from confluent_kafka import Consumer, TopicPartition
from dotenv import load_dotenv

load_dotenv()
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

MARKERS = [
    "aws_iam_role",
    "aws_security_group_rule",
    "aws_acm_certificate",
    "stale-admin-role",
    "permanent-admin-role",
    "ssh_open_world",
    "legacy.acmecorp.local",
]


def tail(topic: str, n: int) -> list[bytes]:
    consumer = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": f"debug-tail-{os.getpid()}",  # groupe jetable, ne touche pas aux vrais offsets
            "enable.auto.commit": False,
        }
    )
    metadata = consumer.list_topics(topic, timeout=10)
    if topic not in metadata.topics or metadata.topics[topic].error is not None:
        print(f"Topic introuvable ou erreur : {topic}")
        consumer.close()
        return []
    partitions = list(metadata.topics[topic].partitions.keys())

    assignments = []
    ends: dict[int, int] = {}
    for p in partitions:
        low, high = consumer.get_watermark_offsets(
            TopicPartition(topic, p), timeout=10, cached=False
        )
        ends[p] = high
        start = max(low, high - n)
        assignments.append(TopicPartition(topic, p, start))
    consumer.assign(assignments)

    values: list[bytes] = []
    remaining = {p: ends[p] - a.offset for p, a in zip(partitions, assignments, strict=True)}
    while any(v > 0 for v in remaining.values()):
        msg = consumer.poll(2.0)
        if msg is None:
            break  # rien de plus à lire (timeout) : on s'arrête, pas de blocage infini
        if msg.error():
            continue
        values.append(msg.value())
        remaining[msg.partition()] = ends[msg.partition()] - (msg.offset() + 1)
    consumer.close()
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("topic")
    parser.add_argument("-n", type=int, default=100, help="messages à lire par partition")
    args = parser.parse_args()

    values = tail(args.topic, args.n)
    print(f"{len(values)} message(s) lus sur {args.topic} (toutes partitions confondues)")

    found = False
    for v in values:
        text = v.decode("utf-8", errors="replace")
        hits = [m for m in MARKERS if m in text]
        if hits:
            found = True
            print(f"MATCH {hits} -> {text[:300]}")

    if not found:
        print("Aucun marqueur Terraform P2.10bis trouvé dans cette fenêtre.")


if __name__ == "__main__":
    main()
