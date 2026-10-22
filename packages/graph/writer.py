# packages/graph/writer.py
import json
import logging
import os
import socket

from confluent_kafka import Consumer, Producer

from packages.core.models.events import NormalizedEvent
from packages.entity_resolution.merger import NodeMerger
from packages.entity_resolution.owner_linker import OwnerLinker  # NOUVEAU (V3, P1.6)
from packages.entity_resolution.resolver import DeterministicResolver
from packages.graph.client import Neo4jClient

logger = logging.getLogger(__name__)

# FIX-3 : ces clés, quand présentes dans attributes, sont recopiées
# comme propriétés top-level du nœud Neo4j, pour un filtrage Cypher
# natif (n.has_mfa = false) au lieu d'un CONTAINS fragile sur le JSON
# (json.dumps ajoute un espace après ':', ce qui casse tout CONTAINS).
NATIVE_PROMOTED_KEYS = [
    "has_mfa", "is_public", "privileged", "run_as_root",
    "contains_pii", "exit_plan_status", "owner",
    "account_enabled", "package_name",
]

# Neo4j n'accepte pas les maps comme valeur de propriété : la criticité DICT
# {"D","I","C","T"} est éclatée en propriétés scalaires criticality_D, etc.
CRITICALITY_AXES = ("D", "I", "C", "T")

# Règle non négociable : aucun nœud sous ce seuil dans le graphe de production.
CONFIDENCE_THRESHOLD = 0.7

UPSERT_NODE_CYPHER = """
MERGE (n:CuzNode {tenant_id: $tenant_id, external_id: $external_id})
ON CREATE SET
  n.id                = $id,
  n.node_type         = $node_type,
  n.name              = $name,
  n.confidence_score  = $confidence_score,
  n.freshness_score   = $freshness_score,
  n.sources           = $sources,
  n.created_at        = $created_at,
  n.updated_at        = $updated_at,
  n.last_seen         = $last_seen,
  n.attributes        = $attributes_json,
  n.tags              = $tags_json,
  n += $native_attrs
ON MATCH SET
  n.id                = $id,
  n.name              = $name,
  n.confidence_score  = $confidence_score,
  n.freshness_score   = $freshness_score,
  n.sources           = $sources,
  n.updated_at        = $updated_at,
  n.last_seen         = $last_seen,
  n.attributes        = $attributes_json,
  n.tags              = $tags_json,
  n += $native_attrs
RETURN n.id as node_id
"""

# NOUVEAU (V3) : upsert d'une arête. MATCH par tenant_id + id interne
# (les CuzEdge portent déjà des CuzNode.id générés par les mappers en
# source_id/target_id, pas des external_id).
UPSERT_EDGE_CYPHER = """
MATCH (a:CuzNode {tenant_id: $tenant_id, id: $source_id})
MATCH (b:CuzNode {tenant_id: $tenant_id, id: $target_id})
MERGE (a)-[r:CUZ_EDGE {
  tenant_id: $tenant_id, edge_type: $edge_type,
  source_id: $source_id, target_id: $target_id
}]->(b)
ON CREATE SET
  r.id               = $id,
  r.confidence_score = $confidence_score,
  r.freshness_score  = $freshness_score,
  r.sources          = $sources,
  r.created_at       = $created_at,
  r.last_seen        = $last_seen,
  r.attributes       = $attributes_json
ON MATCH SET
  r.confidence_score = $confidence_score,
  r.freshness_score  = $freshness_score,
  r.sources          = $sources,
  r.last_seen        = $last_seen,
  r.attributes       = $attributes_json
RETURN r.id as edge_id
"""

class GraphWriter:
    def __init__(self, bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")):
        self.driver = Neo4jClient.get_driver()
        self.resolver = DeterministicResolver()
        self.merger = NodeMerger(self.resolver)
        self.owner_linker = OwnerLinker()  # NOUVEAU (V3)
        # Repos vus avant leur propriétaire : OWNS rattrapé en fin de flux (reconcile_owns)
        self._pending_repos: dict[str, object] = {}
        self.consumer = Consumer({
            "bootstrap.servers": bootstrap_servers,
            "group.id": "cuz-graph-writer",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            # Membership statique : un redémarrage reprend la place sans rebalancing
            # et sans membre fantôme. Une seule réplica par design.
            "group.instance.id": os.getenv("CONSUMER_INSTANCE_ID") or f"cuz-graph-writer-{socket.gethostname()}-{os.getpid()}",
            "session.timeout.ms": 10000,
        })
        self.producer = Producer({"bootstrap.servers": bootstrap_servers})

    def _native_attrs(self, attributes: dict, tags: dict | None = None) -> dict:
        """FIX-3 : extrait les clés promues, en filtrant les None
        (Neo4j n'accepte pas de propriété nulle sur += ).
        La criticité DICT est éclatée en criticality_D/I/C/T."""
        native = {k: v for k, v in attributes.items()
                  if k in NATIVE_PROMOTED_KEYS and v is not None}
        # Tag IaC promu en booléen natif (IaC-DRIFT-001) : les tags sont stockés
        # en JSON, un CONTAINS sur tags_json ne matcherait pas (espace après ':').
        if tags and tags.get("iac_managed") is not None:
            native["iac_managed"] = tags["iac_managed"] == "true"
        # Sous-type de nœud (P2.2 : cloud_alert / recommendation) promu en natif
        if tags and tags.get("node_subtype"):
            native["node_subtype"] = tags["node_subtype"]
        criticality = attributes.get("criticality")
        if isinstance(criticality, dict):
            for axis in CRITICALITY_AXES:
                if criticality.get(axis) is not None:
                    native[f"criticality_{axis}"] = criticality[axis]
        return native

    def _quarantine(self, event: NormalizedEvent) -> None:
        """Nœud sous le seuil de confiance : pas d'écriture Neo4j, publication
        sur cuz.quarantine.{tenant_id} (table PostgreSQL pas encore créée)."""
        logger.warning(
            "node quarantined (confidence %.2f < %.2f): %s",
            event.node.confidence_score, CONFIDENCE_THRESHOLD, event.node.id,
        )
        self.producer.produce(
            topic=f"cuz.quarantine.{event.tenant_id}",
            key=event.event_id.encode(),
            value=event.model_dump_json().encode(),
        )
        self.producer.poll(0)

    def _upsert_node(self, session, event: NormalizedEvent) -> None:
        node = self.merger.merge_or_create(event.node)
        params = {
            "tenant_id":        node.tenant_id,
            "external_id":      node.external_id or node.id,
            "id":               node.id,
            "node_type":        node.node_type.value,
            "name":             node.name,
            "confidence_score": node.confidence_score,
            "freshness_score":  node.freshness_score,
            "sources":          node.sources,
            "created_at":       node.created_at.isoformat(),
            "updated_at":       node.updated_at.isoformat(),
            "last_seen":        node.last_seen.isoformat(),
            "attributes_json":  json.dumps(node.attributes),
            "tags_json":        json.dumps(node.tags),
            "native_attrs":     self._native_attrs(node.attributes, node.tags),  # FIX-3
        }
        session.run(UPSERT_NODE_CYPHER, **params)

        # NOUVEAU (V3, complète P1.6) : alimenter/consommer l'OwnerLinker
        # selon le type de nœud upserté.
        if node.node_type.value == "USER":
            self.owner_linker.register_user(node)
        elif node.node_type.value == "REPOSITORY":
            owns_edge = self.owner_linker.resolve_owns_edge(node)
            if owns_edge:
                self._upsert_edge(session, owns_edge)
                self._pending_repos.pop(node.id, None)
            else:
                self._pending_repos[node.id] = node

    def reconcile_owns(self, session) -> int:
        """Rattrape les arêtes OWNS dont le USER est arrivé après le repo."""
        created = 0
        for repo_id, repo in list(self._pending_repos.items()):
            owns_edge = self.owner_linker.resolve_owns_edge(repo)
            if owns_edge:
                self._upsert_edge(session, owns_edge)
                del self._pending_repos[repo_id]
                created += 1
        logger.info("reconcile_owns: %d arête(s) OWNS créée(s)", created)
        return created

    def _upsert_edge(self, session, edge) -> None:
        """NOUVEAU (V3). Appelé pour les arêtes produites par le Normalizer
        (DEPENDS_ON) et pour l'arête OWNS résolue par OwnerLinker."""
        params = {
            "tenant_id":        edge.tenant_id,
            "id":               edge.id,
            "edge_type":        edge.edge_type.value,
            "source_id":        edge.source_id,
            "target_id":        edge.target_id,
            "confidence_score": edge.confidence_score,
            "freshness_score":  edge.freshness_score,
            "sources":          edge.sources,
            "created_at":       edge.created_at.isoformat(),
            "last_seen":        edge.last_seen.isoformat(),
            "attributes_json":  json.dumps(edge.attributes),
        }
        session.run(UPSERT_EDGE_CYPHER, **params)

    def _publish_mutation(self, event: NormalizedEvent) -> None:
        topic = f"cuz.graph.mutations.{event.tenant_id}"
        self.producer.produce(
            topic=topic,
            key=event.event_id.encode(),
            value=event.model_dump_json().encode(),
        )
        self.producer.poll(0)

    def process_event(self, session, raw_value: bytes) -> None:
        """Traite un NormalizedEvent. Lève une exception en cas d'échec."""
        event = NormalizedEvent.model_validate_json(raw_value.decode())
        if event.node:
            if event.node.confidence_score < CONFIDENCE_THRESHOLD:
                self._quarantine(event)
            else:
                self._upsert_node(session, event)
                self._publish_mutation(event)
        if event.edge:
            self._upsert_edge(session, event.edge)
            self._publish_mutation(event)

    def _dlq(self, tenant_id: str, raw_value: bytes, reason: str) -> bool:
        """Envoie le message en DLQ et attend la confirmation du broker.
        Retourne False si la confirmation n'arrive pas : l'offset ne doit alors PAS être validé."""
        errors: list = []
        self.producer.produce(
            topic=f"cuz.graph.mutations.{tenant_id}.dlq",
            value=raw_value,
            headers=[("reason", reason.encode()[:200])],
            on_delivery=lambda err, _msg: errors.append(err) if err else None,
        )
        return self.producer.flush(timeout=10) == 0 and not errors

    def run(self, tenant_id: str, idle_timeout: float | None = None) -> None:
        """Consomme cuz.normalized. Si idle_timeout (s) est fourni, s'arrête
        après autant de secondes sans message (scan ponctuel).

        Un message en échec part en DLQ ; l'offset n'est validé qu'une fois la DLQ confirmée.
        Sans confirmation, on ne valide rien : le message sera relu au redémarrage."""
        self.consumer.subscribe([f"cuz.normalized.{tenant_id}"])
        with self.driver.session() as session:
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
                        continue
                    try:
                        self.process_event(session, msg.value())
                    except Exception as e:
                        logger.error("GraphWriter error: %s", e)
                        if not self._dlq(tenant_id, msg.value(), f"write_error:{e}"):
                            raise RuntimeError("DLQ non confirmée : arrêt sans validation d'offset") from e
                    self.consumer.commit(message=msg)
                self.reconcile_owns(session)
            finally:
                self.producer.flush(timeout=10)  # ne rien perdre en sortie
                self.consumer.close()


def main() -> None:
    """Point d'entrée Deployment : python -m packages.graph.writer --tenant acmecorp
    Une seule réplica : la résolution d'entités est en mémoire."""
    import argparse

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    GraphWriter().run(args.tenant)


if __name__ == "__main__":
    main()
