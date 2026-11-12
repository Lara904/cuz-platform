# packages/connectors/kubernetes/connector.py
"""Connecteur Kubernetes (P2.1).

RÈGLE 1 : lecture seule (ClusterRole cuz-reader), jamais d'écriture directe dans Neo4j.
Chaque pod est émis avec le uid de son namespace et le nom du cluster : pod, namespace et
cluster partent dans le même message, donc leurs arêtes ne dépendent pas de l'ordre
d'arrivée entre messages.
"""

import asyncio
import logging
import threading
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

from kubernetes import client, config, watch

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import EventType, RawEvent

logger = logging.getLogger(__name__)

WATCH_QUEUE_SIZE = 1000  # borne la mémoire : au-delà, le thread du watch attend (contre-pression)


def _owner_deployment(pod: Any) -> str | None:
    """Deployment propriétaire : ReplicaSet « <deploy>-<hash> » → <deploy>. None si pod nu."""
    for ref in pod.metadata.owner_references or []:
        if ref.kind == "ReplicaSet" and "-" in ref.name:
            return cast(str, ref.name.rsplit("-", 1)[0])
    return None


class KubernetesConnector(IConnector):
    def __init__(self, tenant_id: str, kubeconfig_path: str, cluster_name: str = "acmecorp"):
        super().__init__(tenant_id, {})
        self.cluster_name = cluster_name
        config.load_kube_config(config_file=kubeconfig_path)  # type: ignore[no-untyped-call, unused-ignore]  # stubs kubernetes sans annotations
        self.core_v1 = client.CoreV1Api()

    async def test_connection(self) -> bool:
        try:
            self.core_v1.list_namespace(limit=1)
            return True
        except Exception:
            return False

    @staticmethod
    def _pod_is_public_exposed(pod: Any, services: list[dict[str, Any]]) -> bool:
        """Exposé publiquement = sélectionné par un Service LoadBalancer ou NodePort."""
        pod_labels = pod.metadata.labels or {}
        for svc in services:
            if svc["type"] not in ("LoadBalancer", "NodePort"):
                continue
            selector = svc.get("selector") or {}
            if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                return True
        return False

    def _list_services(self, namespace: str) -> list[dict[str, Any]]:
        return [
            {"name": s.metadata.name, "type": s.spec.type, "selector": s.spec.selector}
            for s in cast(list[Any], self.core_v1.list_namespaced_service(namespace).items)
        ]

    def _pod_record(
        self, pod: Any, namespace: str, namespace_uid: str, services: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Enregistrement d'un pod, identique pour pull_full et le watch : le normalizer n'a qu'une forme."""
        containers = pod.spec.containers or []
        return {
            "uid": pod.metadata.uid,
            "name": pod.metadata.name,
            "namespace": namespace,
            "namespace_uid": namespace_uid,
            "cluster_name": self.cluster_name,
            "node_name": pod.spec.node_name,
            "privileged": any(
                c.security_context and c.security_context.privileged for c in containers
            ),
            "run_as_root": any(
                c.security_context and c.security_context.run_as_user == 0 for c in containers
            ),
            "images": [c.image for c in containers],
            "labels": pod.metadata.labels or {},
            "owner_deployment": _owner_deployment(pod),
            "is_public_exposed": self._pod_is_public_exposed(pod, services),
            "phase": pod.status.phase,
        }

    async def pull_full(self) -> list[RawEvent]:
        events: list[RawEvent] = [self._wrap("cluster", {"name": self.cluster_name})]
        for node in cast(list[Any], self.core_v1.list_node().items):  # nœuds du cluster → SERVER
            events.append(
                self._wrap(
                    "node",
                    {
                        "name": node.metadata.name,
                        "uid": node.metadata.uid,
                        "cluster_name": self.cluster_name,
                    },
                )
            )
        for ns in cast(list[Any], self.core_v1.list_namespace().items):
            ns_name = ns.metadata.name
            ns_raw = {"name": ns_name, "uid": ns.metadata.uid, "cluster_name": self.cluster_name}
            events.append(self._wrap("namespace", ns_raw))
            services = self._list_services(ns_name)
            for pod in cast(list[Any], self.core_v1.list_namespaced_pod(ns_name).items):
                events.append(
                    self._wrap("pod", self._pod_record(pod, ns_name, ns.metadata.uid, services))
                )
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Watch des pods en temps réel. Le watch du client Kubernetes est synchrone : il tourne dans un
        thread et alimente une file bornée, sinon il gèlerait tous les autres flux de la boucle asyncio.
        Chaque événement porte l'enregistrement COMPLET du pod (même forme que pull_full).
        DELETED n'est pas publié : le graphe ne supprime jamais de nœud, la fraîcheur décroît
        (stale-detection P1.14). Un watch interrompu repart après 5 s ; le replay ADDED est idempotent."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[RawEvent] = asyncio.Queue(maxsize=WATCH_QUEUE_SIZE)
        stop = threading.Event()
        watcher = watch.Watch()  # type: ignore[no-untyped-call, unused-ignore]  # stubs kubernetes sans annotations
        namespace_uids: dict[str, str] = {}

        def namespace_uid(name: str) -> str:
            if name not in namespace_uids:
                namespace_uids[name] = cast(Any, self.core_v1.read_namespace(name)).metadata.uid
            return namespace_uids[name]

        def run_watch() -> None:
            while not stop.is_set():
                try:
                    for event in watcher.stream(  # type: ignore[no-untyped-call, unused-ignore]  # stubs kubernetes sans annotations
                        self.core_v1.list_pod_for_all_namespaces, timeout_seconds=60
                    ):
                        if stop.is_set():
                            return
                        if event["type"] not in ("ADDED", "MODIFIED"):
                            continue
                        pod = event["object"]
                        ns = pod.metadata.namespace
                        record = self._pod_record(
                            pod, ns, namespace_uid(ns), self._list_services(ns)
                        )
                        asyncio.run_coroutine_threadsafe(
                            queue.put(self._wrap("pod", record)), loop
                        ).result()
                except Exception as e:  # coupure API, 410 Gone... : on repart
                    logger.warning("watch pods interrompu (%s), reprise dans 5 s", e)
                    stop.wait(5)

        threading.Thread(target=run_watch, name="k8s-pod-watch", daemon=True).start()
        try:
            while True:
                yield await queue.get()
        finally:
            stop.set()
            watcher.stop()  # type: ignore[no-untyped-call, unused-ignore]  # stubs kubernetes sans annotations

    def _wrap(self, object_type: str, data: dict[str, Any]) -> RawEvent:
        return RawEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            source="kubernetes",
            event_type=EventType.NODE_CREATED,
            timestamp=datetime.now(UTC),
            raw_data={"object_type": object_type, **data},
        )
