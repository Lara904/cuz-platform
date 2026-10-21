# packages/loaders/business_process_loader.py
"""Charge des processus métier depuis un CSV et les relie aux assets déjà présents
dans le graphe par une arête SUPPORTS (asset → processus).

Alimentation manuelle assumée : le BIA reste une donnée humaine.
Les nœuds et arêtes passent par le pipeline (cuz.normalized) : aucune écriture
directe dans Neo4j (règle 1). La résolution des assets lit le graphe.

Usage : python -m packages.loaders.business_process_loader --csv tests/fixtures/acmecorp_business_processes.csv --tenant acmecorp
"""
import argparse
import csv
import logging
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness

logger = logging.getLogger(__name__)

# Résout un identifiant d'asset (external_id OU nom) vers l'id du nœud dans le graphe.
# Retourne None si absent ou ambigu : on ne fabrique jamais un lien incertain.
AssetResolver = Callable[[str], str | None]


class BusinessProcessLoader:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def load_csv(self, path: str) -> list[tuple[CuzNode, str]]:
        """Retourne [(nœud BUSINESS_PROCESS, identifiant de l'asset support)]."""
        out: list[tuple[CuzNode, str]] = []
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                last_seen = datetime.now(UTC)
                name = row["process_name"].strip()
                node = CuzNode(
                    id=f"manual:bp-{name}",  # id stable : un rechargement ne duplique rien
                    tenant_id=self.tenant_id,
                    node_type=NodeType.BUSINESS_PROCESS,
                    name=name,
                    external_id=f"bp-{name}",
                    external_ids={"manual": f"bp-{name}"},
                    confidence_score=compute_confidence(["manual"]),
                    freshness_score=compute_freshness(NodeType.BUSINESS_PROCESS, last_seen),
                    sources=["manual"],
                    last_seen=last_seen,
                    attributes={"criticality_raw": row.get("criticality")},
                    tags={"source": "manual", "origin": "business_process_csv"},
                )
                out.append((node, row["supporting_asset_external_id"].strip()))
        return out

    def make_supports_edge(self, process_node: CuzNode, asset_id: str) -> CuzEdge:
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.SUPPORTS,
            source_id=asset_id,
            target_id=process_node.id,
            confidence_score=compute_confidence(["manual"]),
            freshness_score=compute_freshness(NodeType.BUSINESS_PROCESS, datetime.now(UTC)),
            sources=["manual"],
        )

    def build_events(self, path: str, resolve: AssetResolver) -> tuple[list[NormalizedEvent], list[str]]:
        """Événements à publier (nœud + arête par ligne résolue) et liste des lignes non résolues."""
        events: list[NormalizedEvent] = []
        unresolved: list[str] = []
        now = datetime.now(UTC)
        for process, asset_ref in self.load_csv(path):
            asset_id = resolve(asset_ref)
            if asset_id is None:
                unresolved.append(f"{process.name} → {asset_ref}")
                logger.warning("asset non résolu pour '%s' : %s", process.name, asset_ref)
                continue
            base = dict(event_id=str(uuid.uuid4()), raw_event_id="business-process-csv",
                        tenant_id=self.tenant_id, source="manual",
                        event_type=EventType.NODE_CREATED, timestamp=now)
            events.append(NormalizedEvent(node=process, **base))
            events.append(NormalizedEvent(edge=self.make_supports_edge(process, asset_id), **base))
        return events, unresolved


def graph_resolver(session, tenant_id: str) -> AssetResolver:
    """Résolution par external_id, puis par nom si le nom est unique dans le tenant."""
    def resolve(ref: str) -> str | None:
        rows = session.run(
            """MATCH (n:CuzNode {tenant_id: $t})
               WHERE n.external_id = $ref OR n.name = $ref
               RETURN n.id AS id, n.external_id = $ref AS by_ext""",
            t=tenant_id, ref=ref,
        ).data()
        by_ext = [r["id"] for r in rows if r["by_ext"]]
        if len(by_ext) == 1:
            return by_ext[0]
        by_name = [r["id"] for r in rows]
        return by_name[0] if len(by_name) == 1 else None
    return resolve


def main() -> int:
    from dotenv import load_dotenv

    from packages.graph.client import Neo4jClient
    from packages.ingestion.producer import EventProducer

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    loader = BusinessProcessLoader(args.tenant)
    with Neo4jClient.get_driver().session() as session:
        events, unresolved = loader.build_events(args.csv, graph_resolver(session, args.tenant))
    producer = EventProducer()
    for event in events:
        producer.producer.produce(topic=f"cuz.normalized.{args.tenant}", key=event.event_id.encode(),
                                  value=event.model_dump_json().encode())
    producer.flush()
    logger.info("business processes : %d événements publiés, %d lien(s) non résolu(s) %s",
                len(events), len(unresolved), unresolved)
    return 0


if __name__ == "__main__":
    sys.exit(main())
