# packages/detection/freshness_decay.py
"""Décroissance de fraîcheur (CronJob horaire, P1.14).

Recalcule freshness_score de chaque nœud du tenant à partir de last_seen
(compute_freshness) et republie le nœud sur cuz.normalized. Le GraphWriter reste
le seul à écrire dans Neo4j (règle 1).

Usage : python -m packages.detection.freshness_decay --tenant acmecorp
"""
import argparse
import json
import logging
import sys
from datetime import UTC, datetime

from dotenv import load_dotenv

from packages.core.models.enums import NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_freshness
from packages.graph.client import Neo4jClient
from packages.ingestion.producer import EventProducer

load_dotenv()
logger = logging.getLogger("freshness_decay")


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def decayed_node(row: dict, now: datetime) -> CuzNode:
    """Reconstruit le CuzNode d'une ligne Neo4j avec la fraîcheur recalculée."""
    node_type = NodeType(row["node_type"])
    last_seen = _parse_dt(row["last_seen"])
    return CuzNode(
        id=row["id"],
        tenant_id=row["tenant_id"],
        node_type=node_type,
        name=row["name"],
        external_id=row["external_id"],
        external_ids=row["external_ids"] or {},
        confidence_score=row["confidence_score"],
        freshness_score=compute_freshness(node_type, last_seen),
        sources=row["sources"] or [],
        created_at=_parse_dt(row["created_at"]),
        updated_at=now,
        last_seen=last_seen,
        attributes=json.loads(row["attributes"] or "{}"),
        tags=json.loads(row["tags"] or "{}"),
    )


def run(tenant_id: str) -> int:
    now = datetime.now(UTC)
    with Neo4jClient.get_driver().session() as session:
        rows = session.run(
            """MATCH (n:CuzNode {tenant_id: $t})
               RETURN n.id AS id, n.tenant_id AS tenant_id, n.node_type AS node_type,
                      n.name AS name, n.external_id AS external_id, n.external_ids AS external_ids,
                      n.confidence_score AS confidence_score, n.sources AS sources,
                      n.created_at AS created_at, n.last_seen AS last_seen,
                      n.attributes AS attributes, n.tags AS tags""",
            t=tenant_id,
        ).data()
    producer = EventProducer()
    topic = f"cuz.normalized.{tenant_id}"
    published = 0
    for row in rows:
        node = decayed_node(row, now)
        event = NormalizedEvent(
            event_id=f"decay-{node.id}-{now.isoformat()}",
            raw_event_id="freshness-decay",
            tenant_id=tenant_id,
            source="freshness-decay",
            event_type=EventType.NODE_UPDATED,
            timestamp=now,
            node=node,
        )
        producer.producer.produce(topic=topic, key=event.event_id.encode(),
                                  value=event.model_dump_json().encode())
        published += 1
    producer.flush()
    logger.info("freshness-decay : %d nœuds republiés sur %s", published, topic)
    return published


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(args.tenant)
    return 0


if __name__ == "__main__":
    sys.exit(main())
