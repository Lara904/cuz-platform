"""P2.8 : une perte de MFA devient visible dans GET /findings de la VRAIE API, sans recalcul complet.

Lance un uvicorn réel (flux cuz.findings.{tenant} actif) et, sur un tenant jetable, la chaîne
complète : bus -> normalizer -> writer -> Neo4j -> mutations -> MutationConsumer -> cuz.findings ->
API. Le store de l'API n'est calculé qu'UNE fois (premier GET) : un finding qui apparaît ensuite ne
peut venir que du flux réactif, puisque aucun appel à /refresh n'est fait.

Usage : python scripts/measure_findings_link.py [--trials 5] [--port 8765]
"""

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import httpx
from confluent_kafka.admin import AdminClient, NewTopic
from dotenv import load_dotenv

load_dotenv()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from measure_detection_latency import BOOTSTRAP, _exists, _user_event  # noqa: E402

from packages.detection.mutation_consumer import MutationConsumer  # noqa: E402
from packages.graph.client import Neo4jClient  # noqa: E402
from packages.graph.writer import GraphWriter  # noqa: E402
from packages.ingestion.consumer import PipelineConsumer  # noqa: E402
from packages.ingestion.producer import EventProducer  # noqa: E402
from services.api.middleware.auth import Role, create_access_token  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    tenant = f"p28-link-{uuid.uuid4().hex[:6]}"
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

    log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "services.api.main:app", "--port", str(args.port)],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RATE_LIMIT_REQUESTS": "1000000"},  # sondage rapproché, API de test
    )
    base = f"http://127.0.0.1:{args.port}"
    headers = {"Authorization": f"Bearer {create_access_token('probe', Role.VIEWER, tenant)}"}
    url = f"{base}/api/v1/tenants/{tenant}/findings/"
    stop = threading.Event()
    latencies: list[float] = []
    try:
        deadline = time.time() + 60
        while True:
            try:
                if httpx.get(f"{base}/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.time() > deadline or api.poll() is not None:
                print("ÉCHEC : l'API n'a pas démarré")
                return 1
            time.sleep(0.5)

        r = httpx.get(url, headers=headers, timeout=60)  # SEUL calcul complet de ce test
        print(
            f"premier GET /findings (calcul complet) : {r.status_code}, {len(r.json())} finding(s)"
        )
        if r.status_code != 200:
            return 1

        group = f"p28-link-{tenant}"
        threading.Thread(
            target=lambda: PipelineConsumer(BOOTSTRAP, group_id=group).run(tenant), daemon=True
        ).start()
        threading.Thread(
            target=lambda: GraphWriter(BOOTSTRAP, group_id=group).run(tenant), daemon=True
        ).start()
        threading.Thread(
            target=lambda: MutationConsumer(tenant, BOOTSTRAP, group_id=f"{group}-detect").run(
                stop=stop
            ),
            daemon=True,
        ).start()
        producer = EventProducer(BOOTSTRAP)

        producer.publish(_user_event(tenant, "warm", True))
        producer.flush()
        deadline = time.time() + 90
        while not _exists(tenant, "user-warm"):
            if time.time() > deadline:
                print("ÉCHEC : pipeline non prêt en 90 s")
                return 1
            time.sleep(0.25)
        time.sleep(5)  # le flux de l'API doit avoir rejoint le topic (offset latest)

        def api_names() -> set[str]:
            rows = httpx.get(url, headers=headers, timeout=10).json()
            return {n for f in rows if f["rule_id"] == "IAM-001" for n in f["affected_node_names"]}

        for i in range(args.trials):
            uid = f"u{i:02d}"
            producer.publish(_user_event(tenant, uid, True))
            producer.flush()
            while not _exists(tenant, f"user-{uid}"):
                time.sleep(0.05)
            assert f"user-{uid}" not in api_names(), "finding visible avant la perte du MFA"
            t0 = time.time()
            producer.publish(_user_event(tenant, uid, False))
            producer.flush()
            deadline = t0 + 60
            while f"user-{uid}" not in api_names():
                if time.time() > deadline:
                    print(f"  {uid} : finding absent de l'API après 60 s")
                    break
                time.sleep(0.1)
            else:
                latencies.append(time.time() - t0)
        if not latencies:
            return 1
        latencies.sort()
        print(
            f"délai perte de MFA -> visible dans GET /findings de l'API, {len(latencies)}/"
            f"{args.trials} essais : min {latencies[0]:.2f}s, médiane "
            f"{statistics.median(latencies):.2f}s, max {latencies[-1]:.2f}s "
            f"(précision ±0,1 s ; aucun /refresh, un seul calcul complet)"
        )
        return 0 if len(latencies) == args.trials else 1
    finally:
        stop.set()
        api.terminate()
        try:
            api.wait(10)
        except subprocess.TimeoutExpired:
            api.kill()
        if api.returncode not in (0, -15, None):
            log.seek(0)
            print("journal de l'API :\n" + log.read()[-1500:])
        with Neo4jClient.get_driver().session() as s:
            s.run("MATCH (n:CuzNode {tenant_id:$t}) DETACH DELETE n", t=tenant)
        for fut in admin.delete_topics(topics).values():
            try:
                fut.result()
            except Exception:
                pass
        print(f"tenant jetable {tenant} supprimé (nœuds + topics)")
        sys.stdout.flush()
        os._exit(0 if len(latencies) == args.trials else 1)


if __name__ == "__main__":
    sys.exit(main())
