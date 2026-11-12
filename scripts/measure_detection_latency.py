"""P2.8 : délai mutation -> finding IAM-001, et validation du routage sur le graphe réel.

1. Latence : sur un tenant jetable, un utilisateur Entra perd son MFA (publication d'un RawEvent
   has_mfa=false). On mesure le temps jusqu'au finding IAM-001 produit par MutationRouter à partir
   de la mutation publiée par le writer. Chaîne complète : bus -> normalizer -> writer -> Neo4j ->
   topic de mutations -> MutationConsumer -> cuz.findings. Critère de sortie : < 5 min.
2. Routage réel (lecture seule, tenant --tenant) : IAM-001 et ATTACK-PATH-001-PARTIAL sont
   retrouvés en ne lançant que les règles routées ; NET-001 est évalué si une mutation SERVER l'y route.

Usage : python scripts/measure_detection_latency.py [--trials 10] [--tenant acmecorp]
"""

import argparse
import os
import statistics
import sys
import threading
import time
import uuid
from datetime import UTC, datetime

from confluent_kafka import Consumer
from confluent_kafka.admin import AdminClient, NewTopic
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packages.core.models.events import EventType, NormalizedEvent, RawEvent  # noqa: E402
from packages.detection.models import Finding  # noqa: E402
from packages.detection.mutation_consumer import MutationConsumer  # noqa: E402
from packages.detection.mutation_router import MutationRouter, affected_rule_ids  # noqa: E402
from packages.graph.client import Neo4jClient  # noqa: E402
from packages.graph.writer import GraphWriter  # noqa: E402
from packages.ingestion.consumer import PipelineConsumer  # noqa: E402
from packages.ingestion.producer import EventProducer  # noqa: E402

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


def _user_event(tenant: str, uid: str, has_mfa: bool) -> RawEvent:
    return RawEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=tenant,
        source="entra_id",
        event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(UTC),
        raw_data={
            "object_type": "user",
            "record": {
                "id": uid,
                "displayName": f"user-{uid}",
                "userPrincipalName": f"{uid}@acmecorp.test",
                "accountEnabled": True,
                "has_mfa": has_mfa,
                "mfa_methods": [],
            },
        },
    )


def measure_latency(trials: int) -> list[float]:
    tenant = f"p28-latency-{uuid.uuid4().hex[:6]}"
    topics = [
        f"cuz.raw.{tenant}",
        f"cuz.normalized.{tenant}",
        f"cuz.graph.mutations.{tenant}",
        f"cuz.graph.mutations.{tenant}.dlq",
        f"cuz.findings.{tenant}",
    ]
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    for fut in admin.create_topics(
        [NewTopic(t, num_partitions=1, replication_factor=1) for t in topics]
    ).values():
        fut.result()
    group = f"p28-{tenant}"
    threading.Thread(
        target=lambda: PipelineConsumer(BOOTSTRAP, group_id=group).run(tenant), daemon=True
    ).start()
    threading.Thread(
        target=lambda: GraphWriter(BOOTSTRAP, group_id=group).run(tenant), daemon=True
    ).start()

    router = MutationRouter()
    found: dict[str, float] = {}  # nom du user -> instant du finding IAM-001
    stop = threading.Event()

    # Le vrai consumer de production lit les mutations et publie les findings ; on mesure
    # le délai jusqu'à leur arrivée sur cuz.findings.{tenant}.
    detector = MutationConsumer(tenant, BOOTSTRAP, group_id=f"{group}-detect", router=router)
    threading.Thread(target=lambda: detector.run(stop=stop), daemon=True).start()

    def collect() -> None:
        c = Consumer(
            {
                "bootstrap.servers": BOOTSTRAP,
                "group.id": f"{group}-collect",
                "auto.offset.reset": "earliest",
            }
        )
        c.subscribe([f"cuz.findings.{tenant}"])
        while not stop.is_set():
            msg = c.poll(0.1)
            if msg is None or msg.error():
                continue
            finding = Finding.model_validate_json(msg.value())
            if finding.rule_id == "IAM-001":
                for name in finding.affected_node_names:
                    found.setdefault(name, time.time())
        c.close()

    threading.Thread(target=collect, daemon=True).start()
    producer = EventProducer(BOOTSTRAP)
    latencies: list[float] = []
    try:
        # Échauffement : on attend que le pipeline soit prêt (sinon on mesurerait le rebalancing)
        producer.publish(_user_event(tenant, "warm", True))
        producer.flush()
        deadline = time.time() + 90
        while not _exists(tenant, "user-warm"):
            if time.time() > deadline:
                print("ÉCHEC : pipeline non prêt en 90 s")
                return []
            time.sleep(0.25)
        for i in range(trials):
            uid = f"u{i:02d}"
            producer.publish(_user_event(tenant, uid, True))  # a son MFA : pas de finding
            producer.flush()
            while not _exists(tenant, f"user-{uid}"):
                time.sleep(0.05)
            assert f"user-{uid}" not in found, "finding IAM-001 avant la perte du MFA"
            t0 = time.time()
            producer.publish(_user_event(tenant, uid, False))  # perd son MFA
            producer.flush()
            deadline = time.time() + 300
            while f"user-{uid}" not in found and time.time() < deadline:
                time.sleep(0.02)
            if f"user-{uid}" in found:
                assert found[f"user-{uid}"] > t0, "finding antérieur à la mutation"
                latencies.append(found[f"user-{uid}"] - t0)
            else:
                print(f"  {uid} : aucun finding IAM-001 en 300 s")
        print(
            f"requêtes : {router._queries} pour {router._mutations} mutations "
            f"(scan complet = {router.full_scan_queries} par mutation), "
            f"réduction mesurée {router.query_reduction_pct()} %"
        )
        return latencies
    finally:
        stop.set()
        with Neo4jClient.get_driver().session() as s:
            s.run("MATCH (n:CuzNode {tenant_id:$t}) DETACH DELETE n", t=tenant)
        for fut in admin.delete_topics(topics).values():
            try:
                fut.result()
            except Exception:
                pass
        print(f"tenant jetable {tenant} supprimé (nœuds + topics)")


def _exists(tenant: str, name: str) -> bool:
    with Neo4jClient.get_driver().session() as s:
        return bool(
            s.run(
                "MATCH (n:CuzNode {tenant_id:$t, name:$n}) RETURN n LIMIT 1", t=tenant, n=name
            ).data()
        )


def validate_real_graph(tenant: str) -> None:
    """Lecture seule : les règles routées retrouvent bien les findings du graphe réel."""
    router = MutationRouter()
    with Neo4jClient.get_driver().session() as s:
        rows = s.run(
            "MATCH (n:CuzNode {tenant_id:$t}) WHERE n.node_type IN ['USER','SERVER'] "
            "RETURN n.node_type AS t, count(*) AS c",
            t=tenant,
        ).data()
    print(f"graphe {tenant} : {rows}")
    from packages.core.models.edge import CuzEdge
    from packages.core.models.enums import EdgeType, NodeType
    from packages.core.models.node import CuzNode

    def node_ev(nt: NodeType) -> NormalizedEvent:
        n = CuzNode(
            tenant_id=tenant, node_type=nt, name="x", confidence_score=0.9, freshness_score=1.0
        )
        return NormalizedEvent(
            event_id="v", raw_event_id="v", tenant_id=tenant, source="v",
            event_type=EventType.NODE_UPDATED, timestamp=datetime.now(UTC), node=n,
        )  # fmt: skip

    edge = CuzEdge(
        tenant_id=tenant, edge_type=EdgeType.DEPENDS_ON, source_id="a", target_id="b",
        confidence_score=0.9, freshness_score=1.0,
    )  # fmt: skip
    edge_ev = NormalizedEvent(
        event_id="v", raw_event_id="v", tenant_id=tenant, source="v",
        event_type=EventType.EDGE_CREATED, timestamp=datetime.now(UTC), edge=edge,
    )  # fmt: skip
    for label, ev in [
        ("USER muté", node_ev(NodeType.USER)),
        ("SERVER muté", node_ev(NodeType.SERVER)),
        ("arête DEPENDS_ON", edge_ev),
    ]:
        findings = router.run_on_mutation(tenant, ev)
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        print(f"  {label}: règles routées {affected_rule_ids(ev)} -> findings {by_rule}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--tenant", default="acmecorp")
    args = parser.parse_args()
    validate_real_graph(args.tenant)
    lat = measure_latency(args.trials)
    if not lat:
        return 1
    lat.sort()
    print(
        f"délai mutation -> finding IAM-001 sur {len(lat)}/{args.trials} essais : "
        f"min {lat[0]:.3f}s, médiane {statistics.median(lat):.3f}s, max {lat[-1]:.2f}s (critère < 300 s)"
    )
    sys.stdout.flush()
    os._exit(0 if len(lat) == args.trials and lat[-1] < 300 else 1)


if __name__ == "__main__":
    sys.exit(main())
