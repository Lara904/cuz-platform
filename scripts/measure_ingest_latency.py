"""
Latence d'ingestion de bout en bout (P2.7) : publication du RawEvent -> nœud visible dans Neo4j.

Fait passer N événements consécutifs par le VRAI pipeline (Redpanda, PipelineConsumer + Normalizer,
GraphWriter, Neo4j) sur un tenant JETABLE (jamais acmecorp), puis supprime ses nœuds et ses topics.
Mesure : timestamp du RawEvent (instant de publication) -> première lecture du nœud dans Neo4j.
La précision est celle de l'intervalle de sondage (--poll, 50 ms par défaut), pas mieux.

Ne mesure PAS le délai source -> connecteur (ex. K8s API -> watch), ni la latence réseau d'un webhook réel.

Usage : python scripts/measure_ingest_latency.py [--events 100] [--interval 0.2]
"""
import argparse
import os
import statistics
import sys
import threading
import time
import uuid
from datetime import UTC, datetime

from confluent_kafka.admin import AdminClient, NewTopic
from dotenv import load_dotenv

load_dotenv()

from packages.core.models.events import EventType, RawEvent  # noqa: E402
from packages.graph.client import Neo4jClient  # noqa: E402
from packages.graph.writer import GraphWriter  # noqa: E402
from packages.ingestion.consumer import PipelineConsumer  # noqa: E402
from packages.ingestion.producer import EventProducer  # noqa: E402

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092")


def _event(tenant: str, name: str) -> RawEvent:
    return RawEvent(
        event_id=str(uuid.uuid4()), tenant_id=tenant, source="gitea", event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(UTC),
        raw_data={"object_type": "repository", "repo_id": name, "full_name": f"{tenant}/{name}",
                  "name": name, "owner": tenant, "private": True, "default_branch": "main",
                  "dependencies": []})


def _visible(tenant: str) -> dict[str, float]:
    with Neo4jClient.get_driver().session() as s:
        rows = s.run("MATCH (n:CuzNode {tenant_id:$t}) RETURN n.name AS name", t=tenant).data()
    now = time.time()
    return {r["name"]: now for r in rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100)
    parser.add_argument("--interval", type=float, default=0.2, help="secondes entre deux publications")
    parser.add_argument("--poll", type=float, default=0.05)
    parser.add_argument("--keep", action="store_true", help="ne pas nettoyer le tenant jetable")
    args = parser.parse_args()

    tenant = f"p27-latency-{uuid.uuid4().hex[:6]}"
    topics = [f"cuz.raw.{tenant}", f"cuz.normalized.{tenant}", f"cuz.graph.mutations.{tenant}.dlq"]
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    for fut in admin.create_topics([NewTopic(t, num_partitions=1, replication_factor=1) for t in topics]).values():
        fut.result()

    group = f"p27-{tenant}"
    threading.Thread(target=lambda: PipelineConsumer(BOOTSTRAP, group_id=group).run(tenant),
                     daemon=True).start()
    threading.Thread(target=lambda: GraphWriter(BOOTSTRAP, group_id=group).run(tenant),
                     daemon=True).start()
    producer = EventProducer(BOOTSTRAP)

    try:
        # Échauffement : on attend que les consumers aient rejoint leur groupe (sinon la mesure
        # compterait le temps de rebalancing, pas la latence du pipeline).
        warm = _event(tenant, "warmup")
        producer.publish(warm)
        producer.flush()
        deadline = time.time() + 90
        while "warmup" not in _visible(tenant):
            if time.time() > deadline:
                print("ÉCHEC : le pipeline n'a pas traité l'événement d'échauffement en 90 s")
                return 1
            time.sleep(0.25)

        sent: dict[str, datetime] = {}
        seen: dict[str, float] = {}
        stop = threading.Event()

        def poll() -> None:
            while not stop.is_set():
                for name, t in _visible(tenant).items():
                    seen.setdefault(name, t)
                time.sleep(args.poll)

        threading.Thread(target=poll, daemon=True).start()
        for i in range(args.events):
            ev = _event(tenant, f"n{i:03d}")
            sent[ev.raw_data["name"]] = ev.timestamp
            producer.publish(ev)
            producer.flush()
            time.sleep(args.interval)
        deadline = time.time() + 60
        while any(n not in seen for n in sent) and time.time() < deadline:
            time.sleep(0.1)
        stop.set()

        missing = [n for n in sent if n not in seen]
        lat = sorted(seen[n] - sent[n].timestamp() for n in sent if n in seen)
        print(f"événements : {len(sent)} publiés, {len(lat)} visibles, {len(missing)} manquants")
        if lat:
            p95 = lat[max(-(-95 * len(lat) // 100) - 1, 0)]
            print(f"latence publication -> Neo4j : médiane {statistics.median(lat):.3f}s, "
                  f"p95 {p95:.3f}s, max {lat[-1]:.3f}s (précision ±{args.poll * 1000:.0f} ms)")
        return 0 if not missing else 1
    finally:
        if not args.keep:
            with Neo4jClient.get_driver().session() as s:
                s.run("MATCH (n:CuzNode {tenant_id:$t}) DETACH DELETE n", t=tenant)
            # cuz.graph.mutations.{tenant} est créé automatiquement par le writer : à supprimer aussi
            for fut in admin.delete_topics([*topics, f"cuz.graph.mutations.{tenant}"]).values():
                try:
                    fut.result()
                except Exception:
                    pass
            print(f"tenant jetable {tenant} supprimé (nœuds + topics)")
        sys.stdout.flush()
        os._exit(0 if "missing" in dir() and not missing else 1)  # les consumers sont des threads daemon bloquants


if __name__ == "__main__":
    sys.exit(main())
