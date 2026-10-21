# packages/connectors/kubernetes/correlate.py
"""Corrélation K8s ↔ graphe : arêtes AFFECTS et EXPOSES (P2.1).

Ces deux arêtes ne viennent d'aucun connecteur seul : elles croisent des sources.
- AFFECTS  : VULNERABILITY (dépendance d'un repo) → CONTAINER dont une image porte le nom du repo.
- EXPOSES  : CONTAINER exposé publiquement (Service NodePort/LoadBalancer) → STORAGE public.

Les arêtes sont publiées sur cuz.normalized (règle 1) : le GraphWriter les écrit.

Usage : python -m packages.connectors.kubernetes.correlate --tenant acmecorp
"""
import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from dotenv import load_dotenv

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.scoring import compute_confidence, compute_freshness

logger = logging.getLogger("k8s-correlate")


@dataclass(frozen=True)
class GraphNode:
    id: str
    name: str
    node_type: str
    attributes: dict
    dependencies: tuple[str, ...] = ()  # VULNERABILITY ids (repos) ; vide pour les autres


def _repo_segment(image: str) -> str:
    """'acmecorp/backend:latest' → 'backend' ; 'ubuntu:20.04' → 'ubuntu'."""
    path = image.split("@")[0].split(":")[0]
    return path.rsplit("/", 1)[-1].lower()


def correlate(pods: list[GraphNode], repos: list[GraphNode], vulns: dict[str, GraphNode],
              storages: list[GraphNode], tenant_id: str) -> list[CuzEdge]:
    """Fonction pure : calcule AFFECTS et EXPOSES à partir de nœuds déjà lus."""
    edges: list[CuzEdge] = []
    now = datetime.now(UTC)
    repos_by_name = {r.name.lower(): r for r in repos}
    for pod in pods:
        for image in pod.attributes.get("images") or []:
            repo = repos_by_name.get(_repo_segment(image))
            if repo is None:
                continue
            for vuln_id in repo.dependencies:
                vuln = vulns.get(vuln_id)
                if vuln is None:
                    continue
                edges.append(CuzEdge(
                    tenant_id=tenant_id, edge_type=EdgeType.AFFECTS,
                    source_id=vuln.id, target_id=pod.id,
                    confidence_score=compute_confidence(["kubernetes", "gitea"]),
                    freshness_score=compute_freshness(vuln_node_type(), now),
                    sources=["kubernetes", "gitea"],
                    attributes={"resolution_method": "image_name_repo_match", "image": image},
                ))
        if pod.attributes.get("is_public_exposed") is True:
            for storage in storages:
                edges.append(CuzEdge(
                    tenant_id=tenant_id, edge_type=EdgeType.EXPOSES,
                    source_id=pod.id, target_id=storage.id,
                    confidence_score=compute_confidence(["kubernetes", "minio"]),
                    freshness_score=compute_freshness(vuln_node_type(), now),
                    sources=["kubernetes", "minio"],
                    attributes={"resolution_method": "public_service_and_public_bucket"},
                ))
    return edges


def vuln_node_type():
    from packages.core.models.enums import NodeType
    return NodeType.VULNERABILITY


def _read_graph(session, tenant_id: str) -> tuple[list, list, dict, list]:
    def parse(raw):
        try:
            return json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}

    pods = [GraphNode(r["id"], r["name"], "CONTAINER", parse(r["attrs"]))
            for r in session.run(
                "MATCH (p:CuzNode {tenant_id:$t, node_type:'CONTAINER'}) "
                "WHERE 'kubernetes' IN p.sources "
                "RETURN p.id AS id, p.name AS name, p.attributes AS attrs", t=tenant_id).data()]
    repo_rows = session.run(
        """MATCH (r:CuzNode {tenant_id:$t, node_type:'REPOSITORY'})
           OPTIONAL MATCH (r)-[:CUZ_EDGE {edge_type:'DEPENDS_ON'}]->(v:CuzNode {node_type:'VULNERABILITY'})
           RETURN r.id AS id, r.name AS name, collect(v.id) AS deps""", t=tenant_id).data()
    repos = [GraphNode(r["id"], r["name"], "REPOSITORY", {}, tuple(d for d in r["deps"] if d))
             for r in repo_rows]
    vulns = {r["id"]: GraphNode(r["id"], r["name"], "VULNERABILITY", {})
             for r in session.run(
                 "MATCH (v:CuzNode {tenant_id:$t, node_type:'VULNERABILITY'}) "
                 "RETURN v.id AS id, v.name AS name", t=tenant_id).data()}
    storages = [GraphNode(r["id"], r["name"], "STORAGE", {})
                for r in session.run(
                    "MATCH (s:CuzNode {tenant_id:$t, node_type:'STORAGE', is_public:true}) "
                    "RETURN s.id AS id, s.name AS name", t=tenant_id).data()]
    return pods, repos, vulns, storages


def main() -> int:
    from packages.graph.client import Neo4jClient
    from packages.ingestion.producer import EventProducer

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    with Neo4jClient.get_driver().session() as session:
        pods, repos, vulns, storages = _read_graph(session, args.tenant)
    edges = correlate(pods, repos, vulns, storages, args.tenant)
    producer = EventProducer()
    for edge in edges:
        event = NormalizedEvent(
            event_id=str(uuid.uuid4()), raw_event_id=f"k8s-correlate-{uuid.uuid4()}",
            tenant_id=args.tenant, source="kubernetes", event_type=EventType.EDGE_CREATED,
            timestamp=datetime.now(UTC), edge=edge)
        producer.producer.produce(topic=f"cuz.normalized.{args.tenant}", key=event.raw_event_id.encode(),
                                  value=event.model_dump_json().encode())
    producer.flush()
    logger.info("corrélation : %d arête(s) AFFECTS/EXPOSES publiée(s)", len(edges))
    return 0


if __name__ == "__main__":
    sys.exit(main())
