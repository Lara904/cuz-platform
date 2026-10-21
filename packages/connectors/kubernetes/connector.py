# packages/connectors/kubernetes/connector.py
"""Connecteur Kubernetes (P2.1).

RÈGLE 1 : lecture seule (ClusterRole cuz-reader), jamais d'écriture directe dans Neo4j.
Chaque pod est émis avec le uid de son namespace et le nom du cluster : pod, namespace et
cluster partent dans le même message, donc leurs arêtes ne dépendent pas de l'ordre
d'arrivée entre messages.
"""
import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from kubernetes import client, config, watch

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import EventType, RawEvent


class KubernetesConnector(IConnector):
    def __init__(self, tenant_id: str, kubeconfig_path: str, cluster_name: str = "acmecorp"):
        super().__init__(tenant_id, {})
        self.cluster_name = cluster_name
        config.load_kube_config(config_file=kubeconfig_path)
        self.core_v1 = client.CoreV1Api()

    async def test_connection(self) -> bool:
        try:
            self.core_v1.list_namespace(limit=1)
            return True
        except Exception:
            return False

    @staticmethod
    def _pod_is_public_exposed(pod, services: list[dict]) -> bool:
        """Exposé publiquement = sélectionné par un Service LoadBalancer ou NodePort."""
        pod_labels = pod.metadata.labels or {}
        for svc in services:
            if svc["type"] not in ("LoadBalancer", "NodePort"):
                continue
            selector = svc.get("selector") or {}
            if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                return True
        return False

    def _list_services(self, namespace: str) -> list[dict]:
        return [
            {"name": s.metadata.name, "type": s.spec.type, "selector": s.spec.selector}
            for s in self.core_v1.list_namespaced_service(namespace).items
        ]

    async def pull_full(self) -> list[RawEvent]:
        events: list[RawEvent] = [self._wrap("cluster", {"name": self.cluster_name})]
        for node in self.core_v1.list_node().items:  # nœuds du cluster → SERVER
            events.append(self._wrap("node", {"name": node.metadata.name, "uid": node.metadata.uid,
                                              "cluster_name": self.cluster_name}))
        for ns in self.core_v1.list_namespace().items:
            ns_name = ns.metadata.name
            ns_raw = {"name": ns_name, "uid": ns.metadata.uid, "cluster_name": self.cluster_name}
            events.append(self._wrap("namespace", ns_raw))
            services = self._list_services(ns_name)
            for pod in self.core_v1.list_namespaced_pod(ns_name).items:
                containers = pod.spec.containers or []
                events.append(self._wrap("pod", {
                    "uid": pod.metadata.uid,
                    "name": pod.metadata.name,
                    "namespace": ns_name,
                    "namespace_uid": ns.metadata.uid,
                    "cluster_name": self.cluster_name,
                    "node_name": pod.spec.node_name,
                    "privileged": any(c.security_context and c.security_context.privileged
                                      for c in containers),
                    "run_as_root": any(c.security_context and c.security_context.run_as_user == 0
                                       for c in containers),
                    "images": [c.image for c in containers],
                    "labels": pod.metadata.labels or {},
                    "is_public_exposed": self._pod_is_public_exposed(pod, services),
                    "phase": pod.status.phase,
                }))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Référence single-stream. P2.7 la remplacera par des informers multi-ressources.
        Note : le flux sync de `watch` bloque la boucle appelante."""
        w = watch.Watch()
        while True:
            try:
                for event in w.stream(self.core_v1.list_pod_for_all_namespaces, timeout_seconds=300):
                    pod = event["object"]
                    yield self._wrap("pod", {
                        "uid": pod.metadata.uid,
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "cluster_name": self.cluster_name,
                        "event_type_k8s": event["type"],
                    })
            except Exception:
                await asyncio.sleep(5)

    def _wrap(self, object_type: str, data: dict) -> RawEvent:
        return RawEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            source="kubernetes",
            event_type=EventType.NODE_CREATED,
            timestamp=datetime.now(UTC),
            raw_data={"object_type": object_type, **data},
        )
