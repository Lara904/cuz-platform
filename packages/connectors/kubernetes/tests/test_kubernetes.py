# packages/connectors/kubernetes/tests/test_kubernetes.py
import asyncio
import os
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from packages.connectors.kubernetes import connector as connector_mod
from packages.connectors.kubernetes.connector import KubernetesConnector
from packages.connectors.kubernetes.mapper import KubernetesMapper
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.events import EventType, RawEvent
from packages.core.models.node import CuzNode
from packages.ingestion.normalizer import Normalizer

TENANT = "acmecorp"


def _pod_raw(**overrides) -> dict:
    raw = {"uid": "pod-uid-legacy-job", "name": "legacy-job", "namespace": "production",
           "namespace_uid": "ns-uid-production", "cluster_name": "acmecorp",
           "node_name": "k3d-acmecorp-agent-0", "privileged": True, "run_as_root": True,
           "images": ["ubuntu:20.04"], "is_public_exposed": False, "phase": "Running"}
    raw.update(overrides)
    return raw


def _node(node_type, name, ext) -> CuzNode:
    return CuzNode(tenant_id=TENANT, node_type=node_type, name=name, external_id=ext,
                   confidence_score=0.9, freshness_score=0.9, sources=["kubernetes"],
                   last_seen=datetime.now(UTC))


def test_mapper_pod_is_container_with_privileged_flag():
    node = KubernetesMapper(TENANT).map_pod(_pod_raw())
    assert node.node_type == NodeType.CONTAINER
    assert node.attributes["privileged"] is True
    assert node.attributes["is_public_exposed"] is False


def test_mapper_member_of_and_runs_on_edges():
    mapper = KubernetesMapper(TENANT)
    pod = _node(NodeType.CONTAINER, "legacy-job", "pod-uid")
    ns = _node(NodeType.CLUSTER, "acmecorp/production", "ns-uid")
    cluster = _node(NodeType.CLUSTER, "acmecorp", "acmecorp")
    assert mapper.map_member_of_edge(pod, ns).edge_type == EdgeType.MEMBER_OF
    assert mapper.map_runs_on_edge(pod, cluster).edge_type == EdgeType.RUNS_ON


def test_mapper_affects_edge():
    vuln = _node(NodeType.VULNERABILITY, "qs@6.5.2", "qs@6.5.2")
    pod = _node(NodeType.CONTAINER, "legacy-job", "pod-uid")
    assert KubernetesMapper(TENANT).map_affects_edge(vuln, pod).edge_type == EdgeType.AFFECTS


def test_mapper_exposes_edge():
    pod = _node(NodeType.CONTAINER, "legacy-job", "pod-uid")
    bucket = _node(NodeType.STORAGE, "acmecorp-public", "acmecorp-public")
    assert KubernetesMapper(TENANT).map_exposes_edge(pod, bucket).edge_type == EdgeType.EXPOSES


def test_normalizer_pod_produces_three_nodes_and_three_edges_from_one_raw():
    raw = RawEvent(event_id="raw-1", tenant_id=TENANT, source="kubernetes",
                   event_type=EventType.NODE_CREATED, timestamp=datetime.now(UTC),
                   raw_data={"object_type": "pod", **_pod_raw()})
    results = Normalizer().normalize(raw)
    nodes = [r.node for r in results if r.node]
    edges = [r.edge for r in results if r.edge]
    assert {n.node_type for n in nodes} == {NodeType.CLUSTER, NodeType.CONTAINER, NodeType.SERVER}
    assert len(nodes) == 4 and len(edges) == 4  # cluster, namespace, pod, SERVER du node_name
    ids = {n.id for n in nodes}
    assert all(e.source_id in ids and e.target_id in ids for e in edges)  # arêtes sur nœuds émis


def test_normalizer_cluster_node_id_is_stable():
    raw = RawEvent(event_id="raw-2", tenant_id=TENANT, source="kubernetes",
                   event_type=EventType.NODE_CREATED, timestamp=datetime.now(UTC),
                   raw_data={"object_type": "cluster", "name": "acmecorp"})
    assert Normalizer().normalize(raw)[0].node.id == "kubernetes:acmecorp"


# ── Connecteur avec faux client Kubernetes ───────────────────────────────────

def _fake_api(monkeypatch):
    ns = SimpleNamespace(metadata=SimpleNamespace(name="production", uid="ns-uid-production"))
    container = SimpleNamespace(image="ubuntu:20.04", security_context=SimpleNamespace(
        privileged=True, run_as_user=0))
    pod = SimpleNamespace(
        metadata=SimpleNamespace(name="legacy-job", uid="pod-uid-legacy-job", labels={"app": "legacy"},
                                 owner_references=[]),
        spec=SimpleNamespace(containers=[container], node_name="k3d-acmecorp-agent-0"),
        status=SimpleNamespace(phase="Running"))
    svc = SimpleNamespace(metadata=SimpleNamespace(name="legacy-svc"),
                          spec=SimpleNamespace(type="ClusterIP", selector={"app": "legacy"}))

    class FakeCore:
        def list_namespace(self, limit=None):
            return SimpleNamespace(items=[ns])

        def list_node(self):
            node = SimpleNamespace(metadata=SimpleNamespace(name="k3d-acmecorp-agent-0", uid="node-uid"))
            return SimpleNamespace(items=[node])

        def list_namespaced_pod(self, name):
            return SimpleNamespace(items=[pod])

        def list_namespaced_service(self, name):
            return SimpleNamespace(items=[svc])

    monkeypatch.setattr(connector_mod.config, "load_kube_config", lambda config_file: None)
    monkeypatch.setattr(connector_mod.client, "CoreV1Api", FakeCore)


def test_pull_full_emits_cluster_namespace_and_pod(monkeypatch):
    _fake_api(monkeypatch)
    conn = KubernetesConnector(TENANT, kubeconfig_path="unused")
    events = asyncio.run(conn.pull_full())
    types = [e.raw_data["object_type"] for e in events]
    assert types == ["cluster", "node", "namespace", "pod"]
    pod = events[3].raw_data
    assert pod["privileged"] is True and pod["namespace_uid"] == "ns-uid-production"
    assert pod["is_public_exposed"] is False  # ClusterIP : pas exposé


def test_loadbalancer_service_marks_pod_exposed(monkeypatch):
    _fake_api(monkeypatch)
    conn = KubernetesConnector(TENANT, kubeconfig_path="unused")
    pod = SimpleNamespace(metadata=SimpleNamespace(labels={"app": "legacy"}))
    lb = [{"name": "s", "type": "LoadBalancer", "selector": {"app": "legacy"}}]
    assert conn._pod_is_public_exposed(pod, lb) is True


def test_test_connection_false_on_error(monkeypatch):
    class Broken:
        def list_namespace(self, limit=None):
            raise RuntimeError("unreachable")
    monkeypatch.setattr(connector_mod.config, "load_kube_config", lambda config_file: None)
    monkeypatch.setattr(connector_mod.client, "CoreV1Api", Broken)
    conn = KubernetesConnector(TENANT, kubeconfig_path="unused")
    assert asyncio.run(conn.test_connection()) is False


# ── Intégration : cluster k3d réel (skip si KUBECONFIG_PATH absent ou inaccessible) ──

@pytest.mark.skipif(not os.getenv("KUBECONFIG_PATH"), reason="KUBECONFIG_PATH non défini")
def test_live_cluster_reports_legacy_job_privileged():
    conn = KubernetesConnector(TENANT, kubeconfig_path=os.environ["KUBECONFIG_PATH"])
    if not asyncio.run(conn.test_connection()):
        pytest.skip("cluster k3d inaccessible")
    pods = [e.raw_data for e in asyncio.run(conn.pull_full()) if e.raw_data["object_type"] == "pod"]
    legacy = next(p for p in pods if p["name"] == "legacy-job")
    assert legacy["privileged"] is True


def test_namespace_event_links_namespace_to_cluster():
    raw = RawEvent(event_id="raw-3", tenant_id=TENANT, source="kubernetes",
                   event_type=EventType.NODE_CREATED, timestamp=datetime.now(UTC),
                   raw_data={"object_type": "namespace", "name": "empty-ns", "uid": "ns-empty",
                             "cluster_name": "acmecorp"})
    results = Normalizer().normalize(raw)
    edges = [r.edge for r in results if r.edge]
    assert [e.edge_type for e in edges] == [EdgeType.MEMBER_OF]


def test_owner_deployment_from_replicaset_name():
    from packages.connectors.kubernetes.connector import _owner_deployment
    pod = SimpleNamespace(metadata=SimpleNamespace(owner_references=[
        SimpleNamespace(kind="ReplicaSet", name="backend-655845b697")]))
    assert _owner_deployment(pod) == "backend"
    naked = SimpleNamespace(metadata=SimpleNamespace(owner_references=None))
    assert _owner_deployment(naked) is None


# ── P2.7 : watch temps réel ──────────────────────────────────────────────────

def _watch_setup(monkeypatch, events: list[tuple[str, object]]):
    """FakeCore + faux Watch qui rejoue `events` à chaque (re)démarrage du stream."""
    _fake_api(monkeypatch)
    pod = connector_mod.client.CoreV1Api().list_namespaced_pod("production").items[0]
    pod.metadata.namespace = "production"

    class FakeCoreWatch(connector_mod.client.CoreV1Api):
        def read_namespace(self, name):
            return SimpleNamespace(metadata=SimpleNamespace(uid="ns-uid-production"))

        def list_pod_for_all_namespaces(self, **kwargs):  # passé au Watch, jamais appelé en vrai
            raise AssertionError

    class FakeWatch:
        def stream(self, fn, timeout_seconds=None):
            for kind in events:
                yield {"type": kind[0], "object": kind[1] or pod}

        def stop(self):
            pass

    monkeypatch.setattr(connector_mod.client, "CoreV1Api", FakeCoreWatch)
    monkeypatch.setattr(connector_mod.watch, "Watch", FakeWatch)
    return pod


def _take(conn, n: int):
    async def go():
        got = []
        stream = conn.subscribe_events()
        try:
            async for event in stream:
                got.append(event)
                if len(got) == n:
                    break
        finally:
            await stream.aclose()
        return got
    return asyncio.run(asyncio.wait_for(go(), timeout=5))


def test_watch_emits_full_pod_record_same_shape_as_pull_full(monkeypatch):
    _watch_setup(monkeypatch, [("ADDED", None)])
    conn = KubernetesConnector(TENANT, kubeconfig_path="unused")
    watched = _take(conn, 1)[0].raw_data
    full = next(e.raw_data for e in asyncio.run(conn.pull_full()) if e.raw_data["object_type"] == "pod")
    assert watched == full  # le normalizer n'a qu'une forme (namespace_uid, images, privileged...)
    assert watched["namespace_uid"] == "ns-uid-production"


def test_watch_event_is_normalizable_without_dlq(monkeypatch):
    from packages.ingestion.normalizer import Normalizer
    _watch_setup(monkeypatch, [("MODIFIED", None)])
    raw = _take(KubernetesConnector(TENANT, kubeconfig_path="unused"), 1)[0]
    normalized = Normalizer().normalize(raw)
    assert any(e.node and e.node.name == "legacy-job" for e in normalized)
    assert any(e.edge for e in normalized)


def test_watch_ignores_deleted_and_bookmark_events(monkeypatch):
    _watch_setup(monkeypatch, [("DELETED", None), ("BOOKMARK", None), ("ADDED", None)])
    events = _take(KubernetesConnector(TENANT, kubeconfig_path="unused"), 2)
    assert all(e.raw_data["object_type"] == "pod" for e in events)  # jamais de suppression de nœud


def test_watch_does_not_block_the_event_loop(monkeypatch):
    """Le flux K8s est synchrone : s'il tournait dans la boucle, une autre tâche ne progresserait pas."""
    import time

    _watch_setup(monkeypatch, [("ADDED", None)])

    class SlowWatch:
        def stream(self, fn, timeout_seconds=None):
            time.sleep(0.5)  # watch bloquant, comme le vrai client
            yield {"type": "ADDED", "object": connector_mod.client.CoreV1Api().list_namespaced_pod("x").items[0]}

        def stop(self):
            pass

    monkeypatch.setattr(connector_mod.watch, "Watch", SlowWatch)
    conn = KubernetesConnector(TENANT, kubeconfig_path="unused")

    async def go():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.01)

        task = asyncio.create_task(ticker())
        stream = conn.subscribe_events()
        await stream.__anext__()
        await stream.aclose()
        task.cancel()
        return ticks

    assert asyncio.run(asyncio.wait_for(go(), timeout=5)) > 10  # la boucle a continué pendant le watch
