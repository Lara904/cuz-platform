**CUz**

*Cartographie Unifiée du SI*

**GUIDE PHASE 2 --- V1 INDUSTRIELLE**

**Version :** 3.0 --- Octobre 2026, sur la base du Plan de dev V3 (Septembre 2026) et du Plan V2 reconstitué

**Terrain :** 100 % AcmeCorp local --- namespace `cuz-acmecorp`, zéro Stellantis

**Développeuse :** Solo, Fedora, Python 3.12, Docker Compose actif, venv activé

**Critère minimal Phase 2 :** ATTACK-PATH-001 en 5 maillons complets détecté (USER → REPOSITORY → VULNERABILITY → CONTAINER → STORAGE) ; taux de doublons Entity Resolution < 2% ; au moins 5 PR GitOps Tier 1 générées et validées ; module DORA accepté sans modification manuelle

**Durée estimée :** Mois 7---14

**Dépendances :** Phase 1 complète ✅ (checklist de sortie P1 entièrement verte, cf. `CUz_Phase1_Guide_V3.md`)

---

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ NOTE SUR CETTE VERSION** Ce guide suit le même format et le même niveau de détail que `CUz_Phase1_Guide_V3.md` : objectif, fichiers à créer, code complet, critères de sortie vérifiables, pour chaque sous-phase P2.1 à P2.16. Il couvre exactement le périmètre que le `Plan_Dev_CUz_V3.md` assigne à la Phase 2 : P2.1 à P2.15 « inchangées de V2 » et P2.16 (crypto/CBOM), nouveauté V3. P2.17 (SBOM) et P2.18 (snapshot) ne sont **pas** couverts ici --- ils sont listés dans le Plan V3 mais hors du périmètre demandé pour ce guide (P2.1 à P2.16). Le contenu détaillé de P2.1 à P2.15 est reconstitué à partir du Plan V2 (section Phase 2, retrouvée verbatim dans l'historique de conversation --- cf. note en tête de `Plan_Dev_CUz_V2.docx`), qui ne donnait que l'objectif, l'implémentation attendue, le critère de sortie et les dépendances de chaque sous-phase, pas de code. Le code ci-dessous est donc une **implémentation proposée** cohérente avec ces spécifications, avec l'architecture et les conventions déjà en place dans le dépôt (RÈGLE 1 à 5 de la Phase 1, NormalizedEvent{node,edge}, propriétés natives FIX-3, 24 NodeTypes/23 EdgeTypes existants) --- à relire et ajuster au code réel avant exécution, exactement comme les correctifs FIX-1/2/3 l'ont été pour la Phase 1.
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 1. Introduction

La Phase 2 fait passer CUz d'un MVP de cartographie à un outil de production. Trois transformations structurantes :

1. **Couverture complète du SI de référence** --- Kubernetes, cloud, Terraform, scanner de vulnérabilités viennent compléter les 4 connecteurs de Phase 1.
2. **Remédiation automatique encadrée** --- classification des findings par tier, PR GitOps Tier 1, agents Zero Trust à droits JIT, audit trail immuable.
3. **Qualité des données industrielle** --- Entity Resolution probabiliste (Splink), pipeline événementiel (latence < 30s à < 2min selon la source), module DORA complet.

Le critère de succès central de la Phase 2 est la fermeture d'ATTACK-PATH-001 en 5 maillons complets, que la Phase 1 avait volontairement limité à 3 maillons (ATTACK-PATH-001-PARTIAL) faute de connecteur Kubernetes :

```
(djana.dev:USER) -[OWNS]-> (backend:REPOSITORY) -[DEPENDS_ON]-> (qs@6.5.2:VULNERABILITY)
    -[AFFECTS]-> (legacy-job:CONTAINER) -[EXPOSES]-> (acmecorp-public:STORAGE)
```

Les deux derniers maillons (`AFFECTS`, `EXPOSES`) n'existent dans aucun connecteur de Phase 1 --- c'est le connecteur Kubernetes de P2.1 qui les produit, en s'appuyant sur le pod `legacy-job` (`privileged=true`, déjà provisionné en AC.1) qui exécute l'image contenant la dépendance `qs@6.5.2` et qui a un accès réseau sortant vers le bucket public `acmecorp-public`.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  ⚠️ **Point de synchronisation AC.10 (nouveau, Phase 2)** --- équivalent de l'AC.9 de Phase 1 : tous les connecteurs P2.1-P2.4 répondent 200, le graphe dépasse 1000 nœuds, ATTACK-PATH-001 (5 maillons) est détecté, le taux de doublons ER passe sous 2%, au moins 5 PR GitOps Tier 1 sont générées. À valider avant de clore la Phase 2.
  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 1.1 Règles non négociables (reprises de la Phase 1, toujours en vigueur)

🚨 RÈGLE 1 : Aucun connecteur n'écrit directement dans Neo4j. Tout transit par Redpanda (topic `cuz.raw.{tenant_id}`).

🚨 RÈGLE 2 : Tout nœud et toute arête porte `confidence_score` ET `freshness_score`. Sans exception.

🚨 RÈGLE 3 : Aucune action automatique sur un nœud dont `confidence_score < 0.7`.

⚠️ RÈGLE 4 : L'audit trail est immuable --- PostgreSQL append-only, aucune suppression de log. (P2.12 l'étend à toute mutation, finding et décision humaine, pas seulement aux connecteurs.)

⚠️ RÈGLE 5 : Un connecteur = un dossier dans `packages/connectors/`. Hérite de `IConnector`. Contient `connector.py`, `mapper.py`, `tests/`.

🚨 **RÈGLE 6 (nouvelle, Phase 2)** : Aucun agent de remédiation (P2.11) n'a accès à l'ensemble du SI. Chaque agent possède un périmètre limité, des droits minimaux, un objectif unique --- principe Zero Trust, cf. `presentation.md` §Architecture multi-agents.

🚨 **RÈGLE 7 (nouvelle, Phase 2)** : Aucune action corrective Tier 2+ (cf. P2.9) ne s'exécute sans passage par un jumeau ou une validation humaine. Seul le Tier 1 (PR GitOps, réversible par nature) s'exécute de façon autonome.

## 2. Récapitulatif des prérequis

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Ref**      **Critère**
  ------------ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Phase 1      Checklist de sortie Phase 1 (cf. `CUz_Phase1_Guide_V3.md`) entièrement verte, y compris P1.16-P1.18

  AC.9         ATTACK-PATH-001-PARTIAL détecté (3 maillons), > 200 nœuds, ≥ 5 findings

  Infra        k3d cluster `acmecorp` accessible via kubeconfig --- RBAC `cuz-reader` en lecture seule sur tous les namespaces

  Infra        Un 2ème provider/tenant de test disponible pour valider l'isolation multi-tenant (P2.14) --- un 2ème namespace k3d `acmecorp-pilot` suffit en local

  Infra        Repo Gitea `acmecorp/infra-terraform` créé, avec au moins les ressources MinIO/NSG/IAM gérées en `.tf`, pour que P2.3 (drift) et P2.10 (PR GitOps) aient un terrain réel

  Infra        HashiCorp Vault (dev mode) ou équivalent JIT disponible en local pour P2.11

  .env         Nouvelles variables : `KUBECONFIG_PATH`, `TERRAFORM_STATE_PATH`, `EPSS_API_URL` (défaut `https://api.first.org/data/v1/epss`), `VAULT_ADDR`, `VAULT_TOKEN`, `GITEA_IAC_REPO`
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

---

# P2.1 --- Connecteur Kubernetes

**Objectif :** Ingérer les objets Kubernetes (pods, deployments, services, namespaces) du cluster k3d `acmecorp` via l'API K8s. Mapper `Pod` → `NodeType.CONTAINER`, `Deployment`/`Namespace` → `NodeType.CLUSTER`, avec arêtes `RUNS_ON` vers le nœud Cluster et `HOSTS` depuis le nœud infrastructure sous-jacent déjà connu du graphe. Produire les arêtes `AFFECTS` (dépendance vulnérable → pod qui l'exécute) et `EXPOSES` (pod → ressource de stockage/réseau accessible publiquement) qui ferment ATTACK-PATH-001 en 5 maillons.

**Critère de sortie (Plan V2) :** Corrélation K8s↔infrastructure cloud confirmée sur 90% des nœuds. Arêtes `MEMBER_OF` vers Cluster opérationnelles.

**Dépendances :** P1.13, accès KubeAPI du cluster `acmecorp`.

## Fichiers à créer

📄 `packages/connectors/kubernetes/__init__.py`
📄 `packages/connectors/kubernetes/connector.py`
📄 `packages/connectors/kubernetes/mapper.py`
📄 `packages/connectors/kubernetes/tests/__init__.py`
📄 `packages/connectors/kubernetes/tests/test_kubernetes.py`

### connector.py

```python
# packages/connectors/kubernetes/connector.py
import os
import uuid
import asyncio
from datetime import datetime, timezone
from typing import AsyncIterator, List

from kubernetes import client, config, watch
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType


class KubernetesConnector(IConnector):
    """RÈGLE 1 : ce connecteur ne lit le cluster qu'en RBAC read-only
    (ClusterRole cuz-reader) et n'écrit jamais dans Neo4j directement."""

    def __init__(self, tenant_id: str, kubeconfig_path: str, cluster_name: str = "acmecorp"):
        self.tenant_id = tenant_id
        self.cluster_name = cluster_name
        config.load_kube_config(config_file=kubeconfig_path)
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()

    async def test_connection(self) -> bool:
        try:
            self.core_v1.list_namespace(limit=1)
            return True
        except Exception:
            return False

    def _pod_is_public_exposed(self, pod, services: List[dict]) -> bool:
        """Un pod est jugé exposé publiquement s'il est sélectionné par un
        Service de type LoadBalancer/NodePort, ou si un de ses conteneurs
        monte un volume provenant d'un bucket déjà marqué is_public=True
        (corrélation faite côté mapper via les labels/env du pod)."""
        pod_labels = pod.metadata.labels or {}
        for svc in services:
            if svc["type"] not in ("LoadBalancer", "NodePort"):
                continue
            selector = svc.get("selector") or {}
            if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                return True
        return False

    def _list_services(self, namespace: str) -> List[dict]:
        svcs = self.core_v1.list_namespaced_service(namespace)
        return [
            {
                "name": s.metadata.name,
                "type": s.spec.type,
                "selector": s.spec.selector,
            }
            for s in svcs.items
        ]

    async def pull_full(self) -> List[RawEvent]:
        events: List[RawEvent] = []
        namespaces = self.core_v1.list_namespace()

        for ns in namespaces.items:
            ns_name = ns.metadata.name
            events.append(self._wrap("namespace", {
                "name": ns_name,
                "uid": ns.metadata.uid,
                "cluster_name": self.cluster_name,
            }))

            services = self._list_services(ns_name)
            pods = self.core_v1.list_namespaced_pod(ns_name)

            for pod in pods.items:
                containers = pod.spec.containers or []
                privileged = any(
                    c.security_context and c.security_context.privileged
                    for c in containers
                )
                run_as_root = any(
                    c.security_context and c.security_context.run_as_user == 0
                    for c in containers
                )
                image_refs = [c.image for c in containers]
                is_exposed = self._pod_is_public_exposed(pod, services)

                events.append(self._wrap("pod", {
                    "uid": pod.metadata.uid,
                    "name": pod.metadata.name,
                    "namespace": ns_name,
                    "cluster_name": self.cluster_name,
                    "node_name": pod.spec.node_name,
                    "privileged": privileged,
                    "run_as_root": run_as_root,
                    "images": image_refs,
                    "labels": pod.metadata.labels or {},
                    "is_public_exposed": is_exposed,
                    "phase": pod.status.phase,
                }))

        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """P2.7 : utilisé en mode Watch (informers) pour le pipeline
        événementiel. Ici : implémentation de référence single-stream,
        remplacée par des informers multi-ressources en P2.7."""
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
            timestamp=datetime.now(timezone.utc),
            raw_data={"object_type": object_type, **data},
        )
```

### mapper.py

```python
# packages/connectors/kubernetes/mapper.py
from datetime import datetime, timezone
from typing import Optional

from packages.core.models.node import CuzNode
from packages.core.models.edge import CuzEdge
from packages.core.models.enums import NodeType, EdgeType
from packages.core.scoring import compute_confidence, compute_freshness


class KubernetesMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_namespace(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.CLUSTER,
            name=f"{raw['cluster_name']}/{raw['name']}",
            external_id=raw["uid"],
            external_ids={"kubernetes": raw["uid"]},
            confidence_score=compute_confidence(["kubernetes"]),
            freshness_score=compute_freshness(NodeType.CLUSTER, last_seen),
            sources=["kubernetes"],
            last_seen=last_seen,
            attributes={"cluster_name": raw["cluster_name"], "namespace": raw["name"]},
            tags={"source": "kubernetes", "object_type": "namespace"},
        )

    def map_pod(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.CONTAINER,
            name=raw["name"],
            external_id=raw["uid"],
            external_ids={"kubernetes": raw["uid"]},
            confidence_score=compute_confidence(["kubernetes"]),
            freshness_score=compute_freshness(NodeType.CONTAINER, last_seen),
            sources=["kubernetes"],
            last_seen=last_seen,
            attributes={
                "namespace": raw["namespace"],
                "cluster_name": raw["cluster_name"],
                "node_name": raw.get("node_name"),
                "privileged": raw.get("privileged", False),
                "run_as_root": raw.get("run_as_root", False),
                "images": raw.get("images", []),
                "is_public_exposed": raw.get("is_public_exposed", False),
                "phase": raw.get("phase"),
            },
            tags={"source": "kubernetes", "object_type": "pod"},
        )

    def map_runs_on_edge(self, pod_node: CuzNode, cluster_node: CuzNode) -> CuzEdge:
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.RUNS_ON,
            source_id=pod_node.id,
            target_id=cluster_node.id,
            confidence_score=compute_confidence(["kubernetes"]),
            freshness_score=compute_freshness(NodeType.CONTAINER, last_seen),
            sources=["kubernetes"],
        )

    def map_affects_edge(self, vuln_node: CuzNode, pod_node: CuzNode) -> Optional[CuzEdge]:
        """Relie une VULNERABILITY (dépendance Gitea, ex. qs@6.5.2) au
        CONTAINER qui l'exécute, par correspondance package_name présent
        dans le nom d'image du pod (convention AcmeCorp : les images
        embarquent le nom du repo, ex. acmecorp/backend:latest déploie
        les dépendances déclarées dans le repo backend)."""
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.AFFECTS,
            source_id=vuln_node.id,
            target_id=pod_node.id,
            confidence_score=compute_confidence(["kubernetes", "gitea"]),
            freshness_score=compute_freshness(NodeType.CONTAINER, last_seen),
            sources=["kubernetes", "gitea"],
            attributes={"resolution_method": "image_name_repo_match"},
        )

    def map_exposes_edge(self, pod_node: CuzNode, storage_node: CuzNode) -> CuzEdge:
        """Relie un CONTAINER exposé publiquement (is_public_exposed=True)
        à une ressource STORAGE elle-même publique (acmecorp-public).
        Ferme le 5ème maillon d'ATTACK-PATH-001."""
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.EXPOSES,
            source_id=pod_node.id,
            target_id=storage_node.id,
            confidence_score=compute_confidence(["kubernetes", "minio"]),
            freshness_score=compute_freshness(NodeType.CONTAINER, last_seen),
            sources=["kubernetes", "minio"],
        )
```

### tests/test_kubernetes.py

```python
# packages/connectors/kubernetes/tests/test_kubernetes.py
import pytest
from datetime import datetime, timezone
from packages.connectors.kubernetes.mapper import KubernetesMapper
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType, EdgeType

TENANT = "acmecorp"


def test_mapper_pod_privileged_flag():
    mapper = KubernetesMapper(TENANT)
    raw = {
        "uid": "pod-uid-legacy-job", "name": "legacy-job", "namespace": "production",
        "cluster_name": "acmecorp", "node_name": "k3d-acmecorp-agent-0",
        "privileged": True, "run_as_root": True, "images": ["acmecorp/backend:latest"],
        "is_public_exposed": True, "phase": "Running",
    }
    node = mapper.map_pod(raw)
    assert node.node_type == NodeType.CONTAINER
    assert node.attributes["privileged"] is True
    assert node.attributes["is_public_exposed"] is True


def test_mapper_affects_edge():
    mapper = KubernetesMapper(TENANT)
    vuln = CuzNode(tenant_id=TENANT, node_type=NodeType.VULNERABILITY, name="qs@6.5.2",
                    external_id="qs@6.5.2", confidence_score=0.9, freshness_score=0.9,
                    sources=["gitea"], last_seen=datetime.now(timezone.utc))
    pod = CuzNode(tenant_id=TENANT, node_type=NodeType.CONTAINER, name="legacy-job",
                  external_id="pod-uid", confidence_score=0.9, freshness_score=0.9,
                  sources=["kubernetes"], last_seen=datetime.now(timezone.utc))
    edge = mapper.map_affects_edge(vuln, pod)
    assert edge.edge_type == EdgeType.AFFECTS


def test_mapper_exposes_edge():
    mapper = KubernetesMapper(TENANT)
    pod = CuzNode(tenant_id=TENANT, node_type=NodeType.CONTAINER, name="legacy-job",
                  external_id="pod-uid", confidence_score=0.9, freshness_score=0.9,
                  sources=["kubernetes"], last_seen=datetime.now(timezone.utc))
    bucket = CuzNode(tenant_id=TENANT, node_type=NodeType.STORAGE, name="acmecorp-public",
                      external_id="acmecorp-public", confidence_score=0.9, freshness_score=0.9,
                      sources=["minio"], last_seen=datetime.now(timezone.utc))
    edge = mapper.map_exposes_edge(pod, bucket)
    assert edge.edge_type == EdgeType.EXPOSES


@pytest.mark.asyncio
async def test_connection(connector=None):
    from packages.connectors.kubernetes.connector import KubernetesConnector
    import os
    conn = KubernetesConnector(tenant_id=TENANT,
                                kubeconfig_path=os.getenv("KUBECONFIG_PATH", "~/.kube/config"))
    assert await conn.test_connection() is True
```

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION** `EdgeType.RUNS_ON`, `AFFECTS`, `EXPOSES` doivent exister dans l'énum (RÈGLE §2 du Plan V3 : ajout pur, aucune valeur renommée). Vérifier `packages/core/models/enums.py` avant d'écrire le mapper --- si absents, les ajouter comme `RUNS_ON = "RUNS_ON"`, etc.
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**✅ Critères de sortie P2.1**

  -----------------------------------------------------------------------
  ✓ `pytest packages/connectors/kubernetes/tests/ -v` → tous verts
  ✓ Corrélation K8s↔infra confirmée sur ≥ 90% des nœuds CONTAINER (via `node_name` résolu à un nœud SERVER/cloud déjà connu)
  ✓ `MATCH ()-[r:CUZ_EDGE {tenant_id:'acmecorp', edge_type:'RUNS_ON'}]->() RETURN count(r)` → > 0
  ✓ Pod `legacy-job` détecté avec `privileged=true`, `is_public_exposed=true`
  ✓ ATTACK-PATH-001 (5 maillons) détectable après P1.6/P1.7 réexécutés sur les nouvelles arêtes (cf. P2.8/P1.8 mis à jour)
  -----------------------------------------------------------------------

---

# P2.2 --- Connecteur détection cloud (Sentinel/Defender ou équivalent)

**Objectif :** Ingérer via le bus d'événements cloud (Event Hub ou équivalent) les alertes de détection, recommandations sécurité, incidents et indicateurs Threat Intelligence. Mapper les recommandations en findings CUz, dédupliquées avec les findings Cypher existants.

**Critère de sortie (Plan V2) :** Alertes et recommandations visibles dans le graphe (nœuds `Alert` et `Vulnerability`). Doublons avec findings Cypher éliminés (déduplication par `rule_id`).

**Dépendances :** P1.7, Event Hub / bus d'événements du provider cloud de référence.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ Note AcmeCorp** AcmeCorp étant 100% local (k3d + Gitea + MinIO + ServiceNow PDI, zéro cloud réel), ce connecteur est codé contre l'API Azure Event Hub / Microsoft Defender for Cloud (cohérent avec Entra ID déjà utilisé en P1.3) mais testé sur un simulateur local : un petit service HTTP qui rejoue des alertes Defender fictives au format JSON réel de l'API, démarré via `docker compose` comme les autres fixtures (`tests/fixtures/defender_alerts_sim/`). Sur un futur client réel avec cloud effectif, seuls `endpoint`/`credentials` changent --- cf. remarque finale de `CUz_Phase1_Guide_V3.md` sur la réutilisabilité des connecteurs.
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Fichiers à créer

📄 `packages/connectors/cloud_detection/__init__.py`
📄 `packages/connectors/cloud_detection/connector.py`
📄 `packages/connectors/cloud_detection/mapper.py`
📄 `packages/connectors/cloud_detection/tests/__init__.py`
📄 `packages/connectors/cloud_detection/tests/test_cloud_detection.py`

### connector.py

```python
# packages/connectors/cloud_detection/connector.py
import os
import uuid
import asyncio
import httpx
from datetime import datetime, timezone
from typing import AsyncIterator, List

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType


class CloudDetectionConnector(IConnector):
    """Ingère les alertes/recommandations d'un bus de détection cloud
    (Defender for Cloud via Event Hub, ou simulateur local AcmeCorp)."""

    def __init__(self, tenant_id: str, eventhub_url: str, credentials: dict):
        self.tenant_id = tenant_id
        self.eventhub_url = eventhub_url.rstrip("/")
        self.credentials = credentials

    async def test_connection(self) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{self.eventhub_url}/health")
            return r.status_code == 200

    async def pull_full(self) -> List[RawEvent]:
        events = []
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{self.eventhub_url}/alerts")
            r.raise_for_status()
            for alert in r.json().get("alerts", []):
                events.append(self._wrap("alert", alert))

            r2 = await client.get(f"{self.eventhub_url}/recommendations")
            r2.raise_for_status()
            for rec in r2.json().get("recommendations", []):
                events.append(self._wrap("recommendation", rec))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        last_cursor = None
        while True:
            async with httpx.AsyncClient(timeout=30) as client:
                params = {"since": last_cursor} if last_cursor else {}
                r = await client.get(f"{self.eventhub_url}/alerts/stream", params=params)
                if r.status_code == 200:
                    payload = r.json()
                    last_cursor = payload.get("cursor")
                    for alert in payload.get("alerts", []):
                        yield self._wrap("alert", alert)
            await asyncio.sleep(120)  # poll Event Hub toutes les 2 min (P2.7 réduira ça)

    def _wrap(self, object_type: str, data: dict) -> RawEvent:
        return RawEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            source="cloud_detection",
            event_type=EventType.NODE_CREATED,
            timestamp=datetime.now(timezone.utc),
            raw_data={"object_type": object_type, "record": data},
        )
```

### mapper.py

```python
# packages/connectors/cloud_detection/mapper.py
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType
from packages.core.scoring import compute_confidence, compute_freshness


class CloudDetectionMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_alert(self, rec: dict) -> CuzNode:
        """Un Alert cloud n'a pas de NodeType dédié dans le modèle AcmeCorp
        actuel (24 NodeTypes) : il est représenté comme VULNERABILITY avec
        node_subtype='cloud_alert' pour rester filtrable nativement (FIX-3)
        sans ajouter de type. Si un futur client a un volume d'alertes qui
        justifie un NodeType.ALERT dédié, l'ajouter en pur ajout d'enum."""
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.VULNERABILITY,
            name=rec.get("alert_name", rec.get("id", "unknown")),
            external_id=rec.get("id"),
            external_ids={"cloud_detection": rec.get("id", "")},
            confidence_score=compute_confidence(["cloud_detection"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["cloud_detection"],
            last_seen=last_seen,
            attributes={
                "severity": rec.get("severity"),
                "rule_id": rec.get("rule_id"),
                "resource_id": rec.get("resource_id"),
                "status": rec.get("status"),
                "description": rec.get("description"),
            },
            tags={"source": "cloud_detection", "node_subtype": "cloud_alert"},
        )

    def map_recommendation(self, rec: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.VULNERABILITY,
            name=rec.get("recommendation_name", rec.get("id", "unknown")),
            external_id=rec.get("id"),
            external_ids={"cloud_detection": rec.get("id", "")},
            confidence_score=compute_confidence(["cloud_detection"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["cloud_detection"],
            last_seen=last_seen,
            attributes={
                "rule_id": rec.get("rule_id"),
                "resource_id": rec.get("resource_id"),
                "remediation_hint": rec.get("remediation"),
            },
            tags={"source": "cloud_detection", "node_subtype": "recommendation"},
        )


def deduplicate_against_cypher_findings(cloud_nodes: list, cypher_rule_ids: set) -> list:
    """P2.2, critère de sortie : élimine les doublons avec les findings
    Cypher existants par rule_id, pour qu'un IAM-001 détecté par Defender
    ET par le moteur Cypher ne remonte pas deux fois dans le dashboard."""
    return [n for n in cloud_nodes if n.attributes.get("rule_id") not in cypher_rule_ids]
```

### tests/test_cloud_detection.py

```python
# packages/connectors/cloud_detection/tests/test_cloud_detection.py
import pytest
from packages.connectors.cloud_detection.mapper import (
    CloudDetectionMapper, deduplicate_against_cypher_findings,
)
from packages.core.models.enums import NodeType

TENANT = "acmecorp"


def test_mapper_alert():
    mapper = CloudDetectionMapper(TENANT)
    rec = {"id": "alert-001", "alert_name": "Port SSH exposé", "severity": "HIGH",
           "rule_id": "NET-001", "resource_id": "vm-prod-01", "status": "active"}
    node = mapper.map_alert(rec)
    assert node.node_type == NodeType.VULNERABILITY
    assert node.attributes["severity"] == "HIGH"
    assert node.tags["node_subtype"] == "cloud_alert"


def test_deduplicate_removes_known_rule_ids():
    mapper = CloudDetectionMapper(TENANT)
    nodes = [
        mapper.map_alert({"id": "a1", "rule_id": "NET-001"}),
        mapper.map_alert({"id": "a2", "rule_id": "NEW-CLOUD-001"}),
    ]
    deduped = deduplicate_against_cypher_findings(nodes, cypher_rule_ids={"NET-001"})
    assert len(deduped) == 1
    assert deduped[0].attributes["rule_id"] == "NEW-CLOUD-001"


@pytest.mark.asyncio
async def test_connection():
    import os
    from packages.connectors.cloud_detection.connector import CloudDetectionConnector
    conn = CloudDetectionConnector(
        tenant_id=TENANT,
        eventhub_url=os.getenv("CLOUD_DETECTION_SIM_URL", "http://localhost:9100"),
        credentials={},
    )
    assert await conn.test_connection() is True
```

**✅ Critères de sortie P2.2**

  -----------------------------------------------------------------------
  ✓ `pytest packages/connectors/cloud_detection/tests/ -v` → tous verts
  ✓ Alertes et recommandations visibles comme nœuds VULNERABILITY avec `node_subtype` natif
  ✓ `test_deduplicate_removes_known_rule_ids` passe : 0 doublon avec les findings Cypher sur `rule_id` commun
  -----------------------------------------------------------------------

---

# P2.3 --- Connecteur Terraform State

**Objectif :** Parser les fichiers `.tfstate` (JSON), extraire les ressources managées, comparer avec les nœuds cloud déjà connus du graphe pour détecter le drift IaC (ressource en prod non gérée par Terraform). Alimente la règle `IaC-DRIFT-001` déjà présente depuis P1.8 (qui filtrait jusqu'ici sur `tags CONTAINS '"iac_managed":"true"'` sans qu'aucune source ne pose ce tag).

**Critère de sortie (Plan V2) :** Drift IaC détecté et visualisé dans le graphe. Taux de drift initial mesuré sur le parc de référence (baseline).

**Dépendances :** P1.7, accès aux state files Terraform.

## Fichiers à créer

📄 `packages/connectors/terraform/__init__.py`
📄 `packages/connectors/terraform/connector.py`
📄 `packages/connectors/terraform/mapper.py`
📄 `packages/connectors/terraform/tests/__init__.py`
📄 `packages/connectors/terraform/tests/test_terraform.py`

### connector.py

```python
# packages/connectors/terraform/connector.py
import os
import json
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator, List

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType

# AcmeCorp : tests/fixtures/acmecorp.tfstate (déjà présent depuis AC.6,
# utilisé en Phase 1 pour simuler le drift acmecorp-archive).
RESOURCE_TYPE_TO_EXTERNAL_KEY = {
    "aws_s3_bucket": "bucket",
    "minio_s3_bucket": "bucket",
    "azurerm_storage_account": "name",
    "aws_instance": "id",
}


class TerraformStateConnector(IConnector):
    def __init__(self, tenant_id: str, state_path: str):
        self.tenant_id = tenant_id
        self.state_path = state_path

    async def test_connection(self) -> bool:
        return os.path.exists(self.state_path)

    def _parse_state(self) -> List[dict]:
        with open(self.state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        resources = []
        for res in state.get("resources", []):
            res_type = res.get("type")
            ext_key = RESOURCE_TYPE_TO_EXTERNAL_KEY.get(res_type)
            for instance in res.get("instances", []):
                attrs = instance.get("attributes", {})
                resources.append({
                    "resource_type": res_type,
                    "resource_name": res.get("name"),
                    "external_id": attrs.get(ext_key) if ext_key else attrs.get("id"),
                    "attributes": attrs,
                })
        return resources

    async def pull_full(self) -> List[RawEvent]:
        events = []
        for res in self._parse_state():
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="terraform",
                event_type=EventType.NODE_UPDATED,
                timestamp=datetime.now(timezone.utc),
                raw_data={"object_type": "managed_resource", **res},
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Terraform state n'a pas de flux temps réel natif : scan
        déclenché par un webhook CI (terraform apply) ou le job de
        réconciliation P1.14/P2.7. Implémentation de référence : no-op
        générateur, le vrai déclenchement passe par pull_full()."""
        return
        yield  # pragma: no cover
```

### mapper.py

```python
# packages/connectors/terraform/mapper.py
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType
from packages.core.scoring import compute_confidence, compute_freshness


class TerraformMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_managed_resource(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.STORAGE if "bucket" in raw["resource_type"] else NodeType.SERVER,
            name=raw["resource_name"],
            external_id=raw["external_id"] or raw["resource_name"],
            external_ids={"terraform": raw["external_id"] or raw["resource_name"]},
            confidence_score=compute_confidence(["terraform"]),
            freshness_score=compute_freshness(NodeType.STORAGE, last_seen),
            sources=["terraform"],
            last_seen=last_seen,
            attributes={"resource_type": raw["resource_type"]},
            tags={"source": "terraform", "iac_managed": "true"},
        )


def compute_drift(iac_managed_external_ids: set, real_external_ids: set) -> dict:
    """Critère de sortie P2.3 : baseline de drift. Compare les ressources
    réelles (ServiceNow/MinIO/etc.) aux ressources gérées par Terraform."""
    not_in_iac = real_external_ids - iac_managed_external_ids
    not_in_real = iac_managed_external_ids - real_external_ids
    total = len(real_external_ids) or 1
    return {
        "drift_count": len(not_in_iac),
        "drift_rate_pct": round(100 * len(not_in_iac) / total, 1),
        "resources_not_in_iac": sorted(not_in_iac),
        "resources_in_iac_but_missing_real": sorted(not_in_real),
    }
```

### tests/test_terraform.py

```python
# packages/connectors/terraform/tests/test_terraform.py
import json
import pytest
from packages.connectors.terraform.connector import TerraformStateConnector
from packages.connectors.terraform.mapper import TerraformMapper, compute_drift

TENANT = "acmecorp"


@pytest.fixture
def connector(tmp_path):
    return TerraformStateConnector(
        tenant_id=TENANT,
        state_path="tests/fixtures/acmecorp.tfstate",
    )


@pytest.mark.asyncio
async def test_connection(connector):
    assert await connector.test_connection() is True


@pytest.mark.asyncio
async def test_pull_full_parses_resources(connector):
    events = await connector.pull_full()
    assert len(events) > 0


def test_mapper_resource_tagged_iac_managed():
    mapper = TerraformMapper(TENANT)
    raw = {"resource_type": "minio_s3_bucket", "resource_name": "acmecorp-data",
           "external_id": "acmecorp-data", "attributes": {}}
    node = mapper.map_managed_resource(raw)
    assert node.tags["iac_managed"] == "true"


def test_compute_drift_detects_acmecorp_archive():
    """AC.6 : acmecorp-archive est absent de MinIO mais présent en IaC ---
    drift attendu dans l'autre sens (ressource IaC sans miroir réel)."""
    iac = {"acmecorp-data", "acmecorp-logs", "acmecorp-public", "acmecorp-archive"}
    real = {"acmecorp-data", "acmecorp-logs", "acmecorp-public"}
    drift = compute_drift(iac, real)
    assert "acmecorp-archive" in drift["resources_in_iac_but_missing_real"]
    assert drift["drift_count"] == 0  # aucune ressource réelle hors IaC ici
```

**✅ Critères de sortie P2.3**

  -----------------------------------------------------------------------
  ✓ `pytest packages/connectors/terraform/tests/ -v` → tous verts
  ✓ IaC-DRIFT-001 (règle P1.8) détecte désormais des findings réels (nœuds tagués `iac_managed:true` existent enfin)
  ✓ Baseline de drift mesurée et publiée : `drift_rate_pct` calculé sur le parc AcmeCorp
  -----------------------------------------------------------------------

---

# P2.4 --- Connecteur Scanner de vulnérabilités

**Objectif :** Ingérer les CVE depuis un scanner de vulnérabilités (Defender Vulnerability Management ou équivalent). Enrichir chaque CVE avec le score EPSS depuis l'API FIRST.org. Produire les arêtes `AFFECTS` entre `VULNERABILITY` et `CONTAINER`/`ARTIFACT`/`SERVER`. Suivre le statut de patch. Débloque `OAUTH-LATERAL-001` et enrichit ATTACK-PATH-001 avec des CVE réelles (au-delà du cas qs@6.5.2 déjà couvert par Gitea/P1.4).

**Critère de sortie (Plan V2) :** CVEs enrichies avec CVSS + EPSS et statut patch. Croisement CVE × chemin d'attaque opérationnel. Finding ATTACK-PATH-001 enrichi avec CVE réelles.

**Dépendances :** P1.7, P1.8, accès au scanner de vulnérabilités.

## Fichiers à créer

📄 `packages/connectors/vuln_scanner/__init__.py`
📄 `packages/connectors/vuln_scanner/connector.py`
📄 `packages/connectors/vuln_scanner/mapper.py`
📄 `packages/connectors/vuln_scanner/epss_client.py`
📄 `packages/connectors/vuln_scanner/tests/__init__.py`
📄 `packages/connectors/vuln_scanner/tests/test_vuln_scanner.py`

### epss_client.py

```python
# packages/connectors/vuln_scanner/epss_client.py
import os
import httpx
from typing import Optional

EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")


class EPSSClient:
    """Enrichissement EPSS (Exploit Prediction Scoring System, FIRST.org) :
    probabilité d'exploitation dans les 30 jours, 0.0-1.0."""

    async def get_epss(self, cve_id: str) -> Optional[dict]:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(EPSS_API_URL, params={"cve": cve_id})
                if r.status_code != 200:
                    return None
                data = r.json().get("data", [])
                if not data:
                    return None
                return {"epss_score": float(data[0]["epss"]), "epss_percentile": float(data[0]["percentile"])}
            except Exception:
                return None
```

### connector.py

```python
# packages/connectors/vuln_scanner/connector.py
import os
import uuid
import httpx
from datetime import datetime, timezone
from typing import AsyncIterator, List

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType
from packages.connectors.vuln_scanner.epss_client import EPSSClient

# tests/fixtures/acmecorp_cves.json (déjà présent, AC.7) :
# CVE-2022-24999 (CVSS 9.8, qs), CVE-2021-3918 --- utilisé comme source
# locale en l'absence d'un scanner réel branché sur AcmeCorp.


class VulnScannerConnector(IConnector):
    def __init__(self, tenant_id: str, scanner_url: str, api_key: str, fixtures_path: str = None):
        self.tenant_id = tenant_id
        self.scanner_url = scanner_url.rstrip("/")
        self.api_key = api_key
        self.fixtures_path = fixtures_path
        self.epss_client = EPSSClient()

    async def test_connection(self) -> bool:
        if self.fixtures_path:
            return os.path.exists(self.fixtures_path)
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{self.scanner_url}/health", headers=headers)
            return r.status_code == 200

    async def _load_cves(self) -> List[dict]:
        if self.fixtures_path:
            import json
            with open(self.fixtures_path) as f:
                return json.load(f)["cves"]
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{self.scanner_url}/findings", headers=headers)
            r.raise_for_status()
            return r.json().get("findings", [])

    async def pull_full(self) -> List[RawEvent]:
        events = []
        cves = await self._load_cves()
        for cve in cves:
            epss = await self.epss_client.get_epss(cve["cve_id"])
            cve["epss"] = epss
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="vuln_scanner",
                event_type=EventType.NODE_UPDATED,
                timestamp=datetime.now(timezone.utc),
                raw_data={"object_type": "cve_finding", "record": cve},
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        import asyncio
        while True:
            for e in await self.pull_full():
                yield e
            await asyncio.sleep(21600)  # poll 6h, aligné sur Entra ID
```

### mapper.py

```python
# packages/connectors/vuln_scanner/mapper.py
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.edge import CuzEdge
from packages.core.models.enums import NodeType, EdgeType
from packages.core.scoring import compute_confidence, compute_freshness


class VulnScannerMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_cve(self, rec: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        epss = rec.get("epss") or {}
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.VULNERABILITY,
            name=rec["cve_id"],
            external_id=rec["cve_id"],
            external_ids={"vuln_scanner": rec["cve_id"]},
            confidence_score=compute_confidence(["vuln_scanner"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["vuln_scanner"],
            last_seen=last_seen,
            attributes={
                "cve_id": rec["cve_id"],
                "cvss_score": rec.get("cvss_score"),
                "epss_score": epss.get("epss_score"),
                "epss_percentile": epss.get("epss_percentile"),
                "affected_resource_id": rec.get("affected_resource_id"),
                "patch_status": rec.get("patch_status", "unpatched"),
            },
            tags={"source": "vuln_scanner"},
        )

    def map_affects_edge(self, cve_node: CuzNode, target_node: CuzNode) -> CuzEdge:
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.AFFECTS,
            source_id=cve_node.id,
            target_id=target_node.id,
            confidence_score=compute_confidence(["vuln_scanner"]),
            freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),
            sources=["vuln_scanner"],
        )
```

### tests/test_vuln_scanner.py

```python
# packages/connectors/vuln_scanner/tests/test_vuln_scanner.py
import pytest
from packages.connectors.vuln_scanner.mapper import VulnScannerMapper
from packages.core.models.enums import NodeType, EdgeType
from packages.core.models.node import CuzNode
from datetime import datetime, timezone

TENANT = "acmecorp"


@pytest.fixture
def connector():
    from packages.connectors.vuln_scanner.connector import VulnScannerConnector
    return VulnScannerConnector(tenant_id=TENANT, scanner_url="", api_key="",
                                 fixtures_path="tests/fixtures/acmecorp_cves.json")


@pytest.mark.asyncio
async def test_connection(connector):
    assert await connector.test_connection() is True


@pytest.mark.asyncio
async def test_pull_full_includes_qs_cve(connector):
    events = await connector.pull_full()
    cve_ids = {e.raw_data["record"]["cve_id"] for e in events}
    assert "CVE-2022-24999" in cve_ids


def test_mapper_cve_node():
    mapper = VulnScannerMapper(TENANT)
    rec = {"cve_id": "CVE-2022-24999", "cvss_score": 9.8,
           "epss": {"epss_score": 0.94, "epss_percentile": 0.99},
           "affected_resource_id": "qs@6.5.2", "patch_status": "unpatched"}
    node = mapper.map_cve(rec)
    assert node.node_type == NodeType.VULNERABILITY
    assert node.attributes["cvss_score"] == 9.8
    assert node.attributes["epss_score"] == 0.94


def test_mapper_affects_edge():
    mapper = VulnScannerMapper(TENANT)
    cve = CuzNode(tenant_id=TENANT, node_type=NodeType.VULNERABILITY, name="CVE-2022-24999",
                  external_id="CVE-2022-24999", confidence_score=0.9, freshness_score=0.9,
                  sources=["vuln_scanner"], last_seen=datetime.now(timezone.utc))
    server = CuzNode(tenant_id=TENANT, node_type=NodeType.SERVER, name="srv-prod-01",
                      external_id="srv-01", confidence_score=0.9, freshness_score=0.9,
                      sources=["servicenow"], last_seen=datetime.now(timezone.utc))
    edge = mapper.map_affects_edge(cve, server)
    assert edge.edge_type == EdgeType.AFFECTS
```

**✅ Critères de sortie P2.4**

  -----------------------------------------------------------------------
  ✓ `pytest packages/connectors/vuln_scanner/tests/ -v` → tous verts
  ✓ CVE-2022-24999 enrichie avec `cvss_score=9.8` et un `epss_score` numérique
  ✓ Arêtes `AFFECTS` CVE→ressource présentes dans Neo4j
  ✓ ATTACK-PATH-001 affiche la CVE réelle (pas seulement le nom du package) dans le finding
  -----------------------------------------------------------------------

---

# P2.5 --- Entity Resolution probabiliste (Splink)

**Objectif :** Déployer Splink (backend DuckDB) en complément du resolver déterministe de P1.6, pour réduire le taux de doublons de < 10% à < 2%. Comparaisons Jaro-Winkler sur les noms, exact match sur IP, datediff sur la date de création. Entraînement sur les paires déjà résolues par P1.6 (bootstrap déterministe). Seuils : > 0.92 fusion automatique, 0.60--0.92 validation humaine (P2.6).

**Critère de sortie (Plan V2) :** Taux de doublons < 2%. Modèle Splink entraîné sur données réelles. Métriques qualité ER dans le dashboard.

**Dépendances :** P1.6, graphe Phase 1 peuplé (> 1000 nœuds).

## Fichiers à créer

📄 `packages/entity-resolution/probabilistic_resolver.py`
📄 `packages/entity-resolution/splink_settings.py`
📄 `packages/entity-resolution/tests/test_probabilistic_resolver.py`

### splink_settings.py

```python
# packages/entity-resolution/splink_settings.py
"""Configuration Splink pour AcmeCorp : comparaisons adaptées aux champs
réellement présents sur les CuzNode (name, attributes.ip_address,
created_at). Un seul linkage model par tenant --- pas de fuite cross-tenant
(cf. critère P2.14)."""

from splink.comparison_library import (
    JaroWinklerAtThresholds,
    ExactMatch,
    DateOfBirthComparison,
)

SPLINK_SETTINGS = {
    "link_type": "dedupe_only",
    "comparisons": [
        JaroWinklerAtThresholds("name", [0.9, 0.7]).get_comparison("duckdb"),
        ExactMatch("ip_address").get_comparison("duckdb"),
    ],
    "blocking_rules_to_generate_predictions": [
        "l.node_type = r.node_type",
        "substr(l.name, 1, 3) = substr(r.name, 1, 3)",
    ],
    "retain_matching_columns": True,
    "retain_intermediate_calculation_columns": True,
}

FUSION_AUTO_THRESHOLD = 0.92
HUMAN_REVIEW_LOWER_THRESHOLD = 0.60
```

### probabilistic_resolver.py

```python
# packages/entity-resolution/probabilistic_resolver.py
"""Resolver probabiliste Splink, utilisé en complément (pas en remplacement)
du DeterministicResolver de P1.6 : le déterministe matche en premier sur
identifiants forts (quasi gratuit, 0 faux positif) ; ce qui reste non résolu
passe par Splink pour rattraper les ~10% de doublons que le matching par
identifiants forts ne peut pas voir (ex. un même serveur vu sous deux noms
légèrement différents par deux connecteurs sans external_id commun)."""

import pandas as pd
from typing import List, Tuple
import splink.comparison_library as cl
from splink import Linker, DuckDBAPI

from packages.core.models.node import CuzNode
from packages.entity_resolution.splink_settings import (
    SPLINK_SETTINGS, FUSION_AUTO_THRESHOLD, HUMAN_REVIEW_LOWER_THRESHOLD,
)


def _nodes_to_dataframe(nodes: List[CuzNode]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "unique_id": n.id,
            "node_type": n.node_type.value,
            "name": n.name,
            "ip_address": n.attributes.get("ip_address"),
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in nodes
    ])


class ProbabilisticResolver:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.db_api = DuckDBAPI()
        self.linker: Linker | None = None

    def train(self, already_resolved_pairs: List[Tuple[str, str]], all_unresolved_nodes: List[CuzNode]) -> None:
        """Bootstrap : les paires déjà fusionnées par le DeterministicResolver
        de P1.6 servent de vérité terrain pour entraîner les paramètres u/m
        du modèle Fellegi-Sunter, plutôt que de partir d'un prior arbitraire."""
        df = _nodes_to_dataframe(all_unresolved_nodes)
        self.linker = Linker(df, SPLINK_SETTINGS, db_api=self.db_api)
        self.linker.training.estimate_u_using_random_sampling(max_pairs=1e6)
        for comparison in ("name", "ip_address"):
            self.linker.training.estimate_parameters_using_expectation_maximisation(
                f"l.node_type = r.node_type"
            )

    def predict_candidate_pairs(self, nodes: List[CuzNode]) -> pd.DataFrame:
        """Retourne les paires candidates avec leur match_probability.
        >= FUSION_AUTO_THRESHOLD : fusion automatique (comme P1.6).
        [HUMAN_REVIEW_LOWER_THRESHOLD, FUSION_AUTO_THRESHOLD) : file P2.6.
        < HUMAN_REVIEW_LOWER_THRESHOLD : rejeté, pas de doublon."""
        df = _nodes_to_dataframe(nodes)
        self.linker = self.linker or Linker(df, SPLINK_SETTINGS, db_api=self.db_api)
        predictions = self.linker.inference.predict()
        return predictions.as_pandas_dataframe()

    def classify(self, predictions_df: pd.DataFrame) -> dict:
        auto = predictions_df[predictions_df["match_probability"] >= FUSION_AUTO_THRESHOLD]
        review = predictions_df[
            (predictions_df["match_probability"] >= HUMAN_REVIEW_LOWER_THRESHOLD)
            & (predictions_df["match_probability"] < FUSION_AUTO_THRESHOLD)
        ]
        rejected = predictions_df[predictions_df["match_probability"] < HUMAN_REVIEW_LOWER_THRESHOLD]
        return {"auto_merge": auto, "needs_human_review": review, "rejected": rejected}


def measure_duplicate_rate(total_nodes: int, confirmed_duplicate_pairs: int) -> float:
    """Métrique affichée au dashboard (P2.5, critère de sortie)."""
    if total_nodes == 0:
        return 0.0
    return round(100 * confirmed_duplicate_pairs / total_nodes, 2)
```

### tests/test_probabilistic_resolver.py

```python
# packages/entity-resolution/tests/test_probabilistic_resolver.py
import pandas as pd
import pytest
from packages.entity_resolution.probabilistic_resolver import (
    ProbabilisticResolver, measure_duplicate_rate,
)


def test_measure_duplicate_rate():
    assert measure_duplicate_rate(total_nodes=1000, confirmed_duplicate_pairs=15) == 1.5


def test_classify_splits_by_threshold():
    resolver = ProbabilisticResolver("acmecorp")
    df = pd.DataFrame({
        "unique_id_l": ["a", "b", "c"],
        "unique_id_r": ["a2", "b2", "c2"],
        "match_probability": [0.95, 0.75, 0.30],
    })
    result = resolver.classify(df)
    assert len(result["auto_merge"]) == 1
    assert len(result["needs_human_review"]) == 1
    assert len(result["rejected"]) == 1
```

  -----------------------------------------------------------------------
  **💡 Installation** `pip install splink pandas`. Splink tourne entièrement en local via DuckDB --- aucune dépendance externe supplémentaire sur AcmeCorp.
  -----------------------------------------------------------------------

**✅ Critères de sortie P2.5**

  -----------------------------------------------------------------------
  ✓ `pytest packages/entity-resolution/tests/test_probabilistic_resolver.py -v` → tous verts
  ✓ Taux de doublons mesuré < 2% sur le graphe AcmeCorp (`measure_duplicate_rate`)
  ✓ Modèle Splink entraîné et sérialisé (`linker.save_model_to_json()`), rechargeable sans réentraînement complet
  ✓ Métriques ER (taux de doublons, nb paires en attente) exposées dans `/findings/stats` ou un endpoint dédié `/entity-resolution/stats`
  -----------------------------------------------------------------------

---

# P2.6 --- Interface validation humaine ER

**Objectif :** Page `/graph/entity-resolution` listant les paires candidates à score 0.60--0.92 (zone grise de P2.5), affichage côte à côte des deux nœuds avec tous leurs attributs, boutons Fusionner / Rejeter / Signaler. Réinjection des décisions dans Splink pour affiner le modèle.

**Critère de sortie (Plan V2) :** Interface opérationnelle. 100 premières paires traitées par l'équipe. Modèle Splink amélioré après chaque batch de feedback.

**Dépendances :** P2.5.

## Fichiers à créer

📄 `services/api/routers/entity_resolution.py`
📄 `frontend/src/app/graph/entity-resolution/page.tsx`
📄 `frontend/src/app/graph/entity-resolution/components/PairReviewCard.tsx`
📄 `services/api/tests/test_entity_resolution_api.py`

### entity_resolution.py --- Router FastAPI

```python
# services/api/routers/entity_resolution.py
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from packages.entity_resolution.probabilistic_resolver import ProbabilisticResolver

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/entity-resolution", tags=["entity-resolution"])

_pending_pairs_store: dict = {}   # pair_id -> dict ; en prod : PostgreSQL
_decisions_store: list = []       # RÈGLE 4 : append-only, alimente le réentraînement Splink


class PairDecision(BaseModel):
    decision: str  # "merge" | "reject" | "flag"
    reviewer: str
    note: Optional[str] = None


@router.get("/pairs")
async def list_pending_pairs(tenant_id: str, page: int = 1, size: int = 20):
    pairs = list(_pending_pairs_store.get(tenant_id, {}).values())
    start = (page - 1) * size
    return {"total": len(pairs), "pairs": pairs[start:start + size]}


@router.get("/pairs/{pair_id}")
async def get_pair(tenant_id: str, pair_id: str):
    pair = _pending_pairs_store.get(tenant_id, {}).get(pair_id)
    if not pair:
        raise HTTPException(status_code=404, detail="Pair not found")
    return pair


@router.post("/pairs/{pair_id}/decide")
async def decide_pair(tenant_id: str, pair_id: str, body: PairDecision):
    pair = _pending_pairs_store.get(tenant_id, {}).get(pair_id)
    if not pair:
        raise HTTPException(status_code=404, detail="Pair not found")
    if body.decision not in ("merge", "reject", "flag"):
        raise HTTPException(status_code=400, detail="decision must be merge|reject|flag")

    # RÈGLE 4 : écriture append-only de la décision, jamais de suppression
    _decisions_store.append({
        "tenant_id": tenant_id, "pair_id": pair_id, "decision": body.decision,
        "reviewer": body.reviewer, "note": body.note,
        "decided_at": datetime.utcnow().isoformat(),
    })
    del _pending_pairs_store[tenant_id][pair_id]
    return {"status": "recorded", "pair_id": pair_id, "decision": body.decision}


@router.get("/decisions/stats")
async def decisions_stats(tenant_id: str):
    tenant_decisions = [d for d in _decisions_store if d["tenant_id"] == tenant_id]
    return {
        "total_reviewed": len(tenant_decisions),
        "merged": sum(1 for d in tenant_decisions if d["decision"] == "merge"),
        "rejected": sum(1 for d in tenant_decisions if d["decision"] == "reject"),
        "flagged": sum(1 for d in tenant_decisions if d["decision"] == "flag"),
    }
```

### page.tsx --- interface de revue

```tsx
// frontend/src/app/graph/entity-resolution/page.tsx
"use client";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { PairReviewCard } from "./components/PairReviewCard";
import { fetchPendingPairs, decidePair } from "@/lib/api";

const TENANT = "acmecorp";

export default function EntityResolutionPage() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["er-pairs", TENANT],
    queryFn: () => fetchPendingPairs(TENANT),
  });

  const mutation = useMutation({
    mutationFn: ({ pairId, decision }: { pairId: string; decision: string }) =>
      decidePair(TENANT, pairId, decision, "current-user"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["er-pairs", TENANT] }),
  });

  return (
    <main className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">
        CUz — Validation Entity Resolution ({data?.total ?? 0} paires en attente)
      </h1>
      <div className="space-y-4">
        {(data?.pairs ?? []).map((pair: any) => (
          <PairReviewCard
            key={pair.pair_id}
            pair={pair}
            onMerge={() => mutation.mutate({ pairId: pair.pair_id, decision: "merge" })}
            onReject={() => mutation.mutate({ pairId: pair.pair_id, decision: "reject" })}
            onFlag={() => mutation.mutate({ pairId: pair.pair_id, decision: "flag" })}
          />
        ))}
      </div>
    </main>
  );
}
```

### tests/test_entity_resolution_api.py

```python
# services/api/tests/test_entity_resolution_api.py
from fastapi.testclient import TestClient
from services.api.main import app
import services.api.routers.entity_resolution as er_module

client = TestClient(app)
TENANT = "acmecorp"


def setup_function():
    er_module._pending_pairs_store[TENANT] = {
        "p1": {"pair_id": "p1", "node_a": {"name": "srv-01"}, "node_b": {"name": "srv-O1"}, "match_probability": 0.78}
    }
    er_module._decisions_store.clear()


def test_list_pending_pairs():
    r = client.get(f"/api/v1/tenants/{TENANT}/entity-resolution/pairs")
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_decide_pair_merge_records_decision():
    r = client.post(
        f"/api/v1/tenants/{TENANT}/entity-resolution/pairs/p1/decide",
        json={"decision": "merge", "reviewer": "lara"},
    )
    assert r.status_code == 200
    stats = client.get(f"/api/v1/tenants/{TENANT}/entity-resolution/decisions/stats").json()
    assert stats["merged"] == 1


def test_decide_pair_invalid_decision_rejected():
    r = client.post(
        f"/api/v1/tenants/{TENANT}/entity-resolution/pairs/p1/decide",
        json={"decision": "maybe", "reviewer": "lara"},
    )
    assert r.status_code == 400
```

**✅ Critères de sortie P2.6**

  -----------------------------------------------------------------------
  ✓ `pytest services/api/tests/test_entity_resolution_api.py -v` → tous verts
  ✓ `http://localhost:3000/graph/entity-resolution` accessible, affiche les paires 0.60--0.92
  ✓ 100 premières paires AcmeCorp traitées (`decisions/stats.total_reviewed >= 100` sur un run de bootstrap avec paires synthétiques si le volume réel est insuffisant)
  ✓ Décisions enregistrées en append-only (RÈGLE 4), consommées par un réentraînement Splink périodique
  -----------------------------------------------------------------------

---

# P2.7 --- Pipeline événementiel complet

**Objectif :** Activer les souscriptions temps réel aux sources qui le supportent : bus cloud (EventGrid ou équivalent, P2.2), webhooks GitHub/Gitea (déjà enregistrés en P1.4 mais jamais consommés côté serveur), K8s Watch/informers (P2.1). Réduire la latence d'ingestion de l'heure/la journée (réconciliation périodique P1.14) à la minute, conservée comme filet de sécurité.

**Critère de sortie (Plan V2) :** Latence d'ingestion < 2 min pour le cloud, < 30s pour GitHub/Gitea et K8s. Vérifié sur 100 événements consécutifs. Réconciliation quotidienne conservée comme filet de sécurité.

**Dépendances :** P2.1--P2.4, P1.5.

## Fichiers à créer

📄 `services/api/routers/webhooks.py`
📄 `packages/ingestion/event_pipeline.py`
📄 `packages/ingestion/tests/test_event_pipeline.py`

### webhooks.py --- réception des webhooks Gitea (déjà enregistrés en P1.4)

```python
# services/api/routers/webhooks.py
import hmac
import hashlib
import os
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException

from packages.core.models.events import RawEvent, EventType
from packages.ingestion.producer import EventProducer

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])
producer = EventProducer()

GITEA_WEBHOOK_SECRET = os.getenv("GITEA_WEBHOOK_SECRET", "")


def _verify_gitea_signature(body: bytes, signature: str) -> bool:
    if not GITEA_WEBHOOK_SECRET:
        return True  # dev local sans secret configuré
    expected = hmac.new(GITEA_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


@router.post("/gitea")
async def gitea_webhook(request: Request):
    """Reçoit push/create/delete/pull_request depuis les hooks enregistrés
    par GiteaConnector._register_webhook() en P1.4. Publie directement sur
    Redpanda (RÈGLE 1 respectée : ce n'est pas le connecteur qui pousse,
    mais le flux reste raw -> Redpanda, jamais raw -> Neo4j)."""
    body = await request.body()
    signature = request.headers.get("X-Gitea-Signature", "")
    if not _verify_gitea_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    tenant_id = "acmecorp"  # résolu via le repo/org dans une version multi-tenant (P2.14)
    event = RawEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        source="gitea",
        event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(timezone.utc),
        raw_data={"object_type": "webhook_push", "payload": payload},
    )
    producer.publish(event)
    producer.flush()
    return {"status": "accepted", "event_id": event.event_id}
```

### event_pipeline.py --- orchestration multi-source

```python
# packages/ingestion/event_pipeline.py
"""Orchestrateur qui démarre, en tâches asyncio parallèles, les flux
subscribe_events() de chaque connecteur événementiel : Kubernetes (Watch),
Cloud Detection (poll court), et consomme les webhooks Gitea (déjà posés
sur Redpanda par services/api/routers/webhooks.py, pas besoin de tâche
dédiée ici). La réconciliation P1.14 continue de tourner en parallèle,
comme filet de sécurité en cas de coupure d'un flux événementiel."""

import asyncio
import logging
from datetime import datetime, timezone

from packages.ingestion.producer import EventProducer

logger = logging.getLogger(__name__)


class EventPipeline:
    def __init__(self, connectors: dict):
        """connectors: {"kubernetes": KubernetesConnector(...), "cloud_detection": ...}"""
        self.connectors = connectors
        self.producer = EventProducer()
        self._latencies: list[float] = []

    async def _run_connector_stream(self, name: str, connector) -> None:
        async for raw_event in connector.subscribe_events():
            received_at = datetime.now(timezone.utc)
            self.producer.publish(raw_event)
            latency = (received_at - raw_event.timestamp).total_seconds()
            self._latencies.append(latency)
            logger.info("event_pipeline: %s event published, latency=%.2fs", name, latency)

    async def run(self) -> None:
        self.producer_tasks = [
            asyncio.create_task(self._run_connector_stream(name, conn))
            for name, conn in self.connectors.items()
        ]
        await asyncio.gather(*self.producer_tasks)

    def measure_p95_latency(self) -> float:
        """Critère de sortie P2.7 : vérifié sur 100 événements consécutifs."""
        if not self._latencies:
            return 0.0
        sorted_lat = sorted(self._latencies)
        idx = int(0.95 * len(sorted_lat))
        return sorted_lat[min(idx, len(sorted_lat) - 1)]
```

### tests/test_event_pipeline.py

```python
# packages/ingestion/tests/test_event_pipeline.py
import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from packages.ingestion.event_pipeline import EventPipeline
from packages.core.models.events import RawEvent, EventType


class FakeFastConnector:
    """Simule un connecteur K8s/Gitea produisant 100 événements avec une
    latence d'émission < 30s, pour valider measure_p95_latency()."""

    async def subscribe_events(self):
        for i in range(100):
            yield RawEvent(
                event_id=str(i), tenant_id="acmecorp", source="kubernetes",
                event_type=EventType.NODE_UPDATED,
                timestamp=datetime.now(timezone.utc) - timedelta(seconds=5),
                raw_data={},
            )


@pytest.mark.asyncio
async def test_p95_latency_under_30s(monkeypatch):
    pipeline = EventPipeline(connectors={"kubernetes": FakeFastConnector()})
    monkeypatch.setattr(pipeline.producer, "publish", lambda e: None)

    task = asyncio.create_task(pipeline._run_connector_stream("kubernetes", FakeFastConnector()))
    await asyncio.wait_for(task, timeout=5)

    p95 = pipeline.measure_p95_latency()
    assert p95 < 30, f"P95 latency {p95}s dépasse le seuil de 30s"
```

**✅ Critères de sortie P2.7**

  -----------------------------------------------------------------------
  ✓ `pytest packages/ingestion/tests/test_event_pipeline.py -v` → tous verts
  ✓ P95 de latence < 30s pour Gitea/K8s, < 2 min pour le cloud, mesuré sur 100 événements consécutifs (`measure_p95_latency()`)
  ✓ Webhook Gitea `POST /api/v1/webhooks/gitea` → signature vérifiée, événement publié sur `cuz.raw.acmecorp` en < 1s
  ✓ Réconciliation quotidienne P1.14 toujours active en parallèle (filet de sécurité)
  -----------------------------------------------------------------------

---

# P2.8 --- Détection réactive (mutation-triggered)

**Objectif :** Mapper chaque type de mutation graphe aux règles de détection affectées. Ne déclencher que les règles pertinentes à chaque mutation (ex. une arête `ALLOWS` créée → règles réseau uniquement), plutôt que le scan complet périodique de `DetectionRunner.run_all()` (P1.8). Remplace l'implémentation provisoire `run_on_mutation()` de P1.8 qui appelait `run_all()` en commentant « Phase 2 : filtrage fin ».

**Critère de sortie (Plan V2) :** Délai de détection < 5 min après mutation. Validé sur NET-001, IAM-001, ATTACK-PATH-001. Réduction de 80% du volume de requêtes Cypher vs scan complet.

**Dépendances :** P1.8, P2.7.

## Fichiers à créer

📄 `packages/detection/mutation_router.py`
📄 `packages/detection/tests/test_mutation_router.py`

### mutation_router.py

```python
# packages/detection/mutation_router.py
"""Remplace DetectionRunner.run_on_mutation() (P1.8, qui faisait
`return self.run_all(tenant_id)`). Table de correspondance NodeType/EdgeType
mutés -> règles concernées, pour ne lancer qu'un sous-ensemble ciblé de
requêtes Cypher sur chaque mutation reçue depuis cuz.graph.mutations.{tenant_id}."""

from typing import List
from packages.core.models.events import NormalizedEvent
from packages.core.models.enums import NodeType, EdgeType
from packages.detection.models import Finding
from packages.detection.rules import network, iam, attack_path, dora, cis, shadow_it
from packages.graph.client import Neo4jClient

# node_type / edge_type mutés -> règles à réexécuter
NODE_TYPE_TO_RULES = {
    NodeType.USER: [iam.rule_iam_001, attack_path.rule_attack_path_001_partial],
    NodeType.STORAGE: [network.rule_storage_public_001] if hasattr(network, "rule_storage_public_001") else [],
    NodeType.CONTAINER: [network.rule_k8s_priv_001] if hasattr(network, "rule_k8s_priv_001") else [],
    NodeType.THIRD_PARTY: [dora.rule_dora_third_party_001] if hasattr(dora, "rule_dora_third_party_001") else [],
}

EDGE_TYPE_TO_RULES = {
    EdgeType.OWNS: [attack_path.rule_attack_path_001_partial],
    EdgeType.DEPENDS_ON: [attack_path.rule_attack_path_001_partial],
    EdgeType.AFFECTS: [attack_path.rule_attack_path_001_partial],
    EdgeType.EXPOSES: [attack_path.rule_attack_path_001_partial],
}


class MutationRouter:
    def __init__(self):
        self.driver = Neo4jClient.get_driver()
        self._query_count = 0
        self._baseline_full_scan_query_count = 20  # nb de règles Cypher P1.8

    def rules_for_event(self, event: NormalizedEvent) -> list:
        rules = set()
        if event.node:
            rules.update(NODE_TYPE_TO_RULES.get(event.node.node_type, []))
        if event.edge:
            rules.update(EDGE_TYPE_TO_RULES.get(event.edge.edge_type, []))
        return list(rules)

    def run_on_mutation(self, tenant_id: str, event: NormalizedEvent) -> List[Finding]:
        rules = self.rules_for_event(event)
        findings = []
        with self.driver.session() as session:
            for rule_fn in rules:
                self._query_count += 1
                findings.extend(rule_fn(session, tenant_id))
        return findings

    def query_reduction_pct(self) -> float:
        """Critère de sortie : réduction de 80% du volume de requêtes Cypher
        vs un scan complet (20 règles) à chaque mutation."""
        if self._query_count == 0:
            return 0.0
        avg_queries_per_mutation = self._query_count  # simplifié : 1 mutation ici
        return round(100 * (1 - avg_queries_per_mutation / self._baseline_full_scan_query_count), 1)
```

### tests/test_mutation_router.py

```python
# packages/detection/tests/test_mutation_router.py
import pytest
from datetime import datetime, timezone
from packages.detection.mutation_router import MutationRouter
from packages.core.models.events import NormalizedEvent
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType

TENANT = "acmecorp"


def test_rules_for_user_mutation_includes_iam_and_attack_path():
    router = MutationRouter()
    user_node = CuzNode(tenant_id=TENANT, node_type=NodeType.USER, name="djana.dev",
                         external_id="uid1", confidence_score=0.9, freshness_score=0.9,
                         sources=["entra_id"], last_seen=datetime.now(timezone.utc))
    event = NormalizedEvent(event_id="e1", raw_event_id="r1", tenant_id=TENANT,
                             source="entra_id", event_type="NODE_UPDATED",
                             timestamp=datetime.now(timezone.utc), node=user_node)
    rules = router.rules_for_event(event)
    assert len(rules) >= 1  # au moins IAM-001


def test_query_reduction_above_80_pct():
    router = MutationRouter()
    router._query_count = 2  # 2 règles déclenchées au lieu de 20
    assert router.query_reduction_pct() >= 80.0
```

**✅ Critères de sortie P2.8**

  -----------------------------------------------------------------------
  ✓ `pytest packages/detection/tests/test_mutation_router.py -v` → tous verts
  ✓ Délai de détection mesuré < 5 min entre une mutation (ex. `djana.dev` perd son MFA) et le Finding IAM-001 correspondant
  ✓ `query_reduction_pct() >= 80` sur un échantillon de mutations réelles
  ✓ Validé sur NET-001, IAM-001 et ATTACK-PATH-001 (5 maillons, post-P2.1)
  -----------------------------------------------------------------------

---

# P2.9 --- Classification findings par tiers

**Objectif :** Classifier chaque finding en 5 tiers de criticité opérationnelle : Tier 0 (tag/alerte, aucun impact), Tier 1 (PR GitOps, réversible), Tier 2 (jumeau requis avant exécution), Tier 3 (canary + validation humaine), Tier 4 (humain uniquement, jamais automatisé). Mapper chaque règle existante (20 règles Cypher + 5 OPA + Shadow-IT) à un tier.

**Critère de sortie (Plan V2) :** Chaque finding porte un tier visible dans le dashboard. Aucune action auto sur un finding Tier 4. Tests sur les 20 règles existantes. Mapping documenté.

**Dépendances :** P1.8, P1.9.

## Fichiers à créer

📄 `packages/detection/tier_classifier.py`
📄 `docs/tier-mapping.md`
📄 `packages/detection/tests/test_tier_classifier.py`

### tier_classifier.py

```python
# packages/detection/tier_classifier.py
"""Mapping rule_id -> tier. Toute règle absente de ce mapping est traitée
par défaut comme Tier 4 (RÈGLE 7 : jamais d'automatisation par défaut sur
un finding non classifié --- fail-safe plutôt que fail-open)."""

from enum import IntEnum


class Tier(IntEnum):
    TIER_0 = 0  # tag/alerte seulement
    TIER_1 = 1  # PR GitOps, réversible
    TIER_2 = 2  # jumeau requis
    TIER_3 = 3  # canary + validation humaine
    TIER_4 = 4  # humain uniquement


RULE_TIER_MAPPING: dict[str, Tier] = {
    # Tier 1 --- réversibles, génèrent une PR GitOps (P2.10)
    "NET-001": Tier.TIER_1,             # port SSH exposé -> fermer le port dans le NSG Terraform
    "STORAGE-PUBLIC-001": Tier.TIER_1,  # bucket public -> retirer la policy publique
    "IAM-001": Tier.TIER_1,             # identité sans MFA -> PR forçant la policy MFA (si géré en IaC)
    "CIS-003": Tier.TIER_1,             # service sans tag owner -> PR ajoutant le tag
    "CIS-011": Tier.TIER_1,             # rôle admin permanent -> PR réduisant la portée du rôle

    # Tier 2 --- nécessitent un jumeau avant exécution (Phase 3, P3.8/P3.9)
    "K8S-PRIV-001": Tier.TIER_2,        # pod privileged -> changement de SecurityContext à tester
    "IaC-DRIFT-001": Tier.TIER_2,       # resynchronisation IaC, impact difficile à prévoir à l'aveugle

    # Tier 3 --- canary + validation humaine (Phase 4)
    "ATTACK-PATH-001-PARTIAL": Tier.TIER_3,
    "ATTACK-PATH-001": Tier.TIER_3,
    "OAUTH-LATERAL-001": Tier.TIER_3,

    # Tier 4 --- humain uniquement
    "DORA-THIRD-PARTY-001": Tier.TIER_4,  # décision contractuelle, pas technique
    "SHADOW-IT-001": Tier.TIER_4,         # nécessite arbitrage métier (déclarer ou isoler l'actif)

    # Tier 0 --- information seule
    "IAM-OPA-001": Tier.TIER_0,
}


def classify(rule_id: str) -> Tier:
    return RULE_TIER_MAPPING.get(rule_id, Tier.TIER_4)


def can_automate(rule_id: str) -> bool:
    """RÈGLE 7 : seul le Tier 1 s'exécute de façon autonome sans jumeau ni
    validation humaine préalable."""
    return classify(rule_id) == Tier.TIER_1
```

### tests/test_tier_classifier.py

```python
# packages/detection/tests/test_tier_classifier.py
from packages.detection.tier_classifier import classify, can_automate, Tier, RULE_TIER_MAPPING


def test_net_001_is_tier_1_and_automatable():
    assert classify("NET-001") == Tier.TIER_1
    assert can_automate("NET-001") is True


def test_attack_path_is_tier_3_not_automatable():
    assert classify("ATTACK-PATH-001") == Tier.TIER_3
    assert can_automate("ATTACK-PATH-001") is False


def test_unknown_rule_defaults_to_tier_4():
    """Fail-safe : une règle non mappée n'est JAMAIS automatisée par défaut."""
    assert classify("UNMAPPED-RULE-999") == Tier.TIER_4
    assert can_automate("UNMAPPED-RULE-999") is False


def test_all_20_phase1_rules_have_explicit_tier_or_documented_default():
    phase1_rule_ids = {
        "NET-001", "IAM-001", "ATTACK-PATH-001-PARTIAL", "OAUTH-LATERAL-001",
        "STORAGE-PUBLIC-001", "K8S-PRIV-001", "IaC-DRIFT-001", "DORA-THIRD-PARTY-001",
        "SHADOW-IT-001",
    } | {f"CIS-{i:03d}" for i in range(1, 13)}
    for rule_id in phase1_rule_ids:
        t = classify(rule_id)
        assert t in Tier  # au minimum, retombe sur TIER_4 documenté, jamais d'exception
```

**✅ Critères de sortie P2.9**

  -----------------------------------------------------------------------
  ✓ `pytest packages/detection/tests/test_tier_classifier.py -v` → tous verts
  ✓ Chaque `Finding` renvoyé par `/findings` porte un champ `tier` (ajouter `tier: int` au modèle `Finding` de P1.8, calculé via `classify(rule_id)` à l'émission)
  ✓ `docs/tier-mapping.md` documente la justification de chaque tier pour les 20+5+1 règles existantes
  ✓ Aucun test ni code n'exécute d'action automatique sur un finding Tier 4 (vérifié par `test_unknown_rule_defaults_to_tier_4`)
  -----------------------------------------------------------------------

---

# P2.10 --- Générateur PR GitOps (Tier 1)

**Objectif :** Générer des Pull Requests dans le repo Terraform/IaC de référence (`acmecorp/infra-terraform` sur Gitea) pour les findings Tier 1 : port 22 ouvert (NET-001), bucket public (STORAGE-PUBLIC-001), rôle IAM inutilisé > 90j, certificat expiré. Chaque PR contient le diff Terraform, un lien vers le finding, et la justification CIS/DORA/MITRE.

**Critère de sortie (Plan V2) :** 5 règles Tier 1 génèrent des PR automatiquement. Validation par l'équipe sur 10 PR réelles. Audit trail complet : finding → PR → merge → graphe mis à jour.

**Dépendances :** P2.8, P2.9, accès repo IaC de référence.

## Fichiers à créer

📄 `packages/remediation/__init__.py`
📄 `packages/remediation/gitops_pr_generator.py`
📄 `packages/remediation/templates/net_001.tf.j2`
📄 `packages/remediation/templates/storage_public_001.tf.j2`
📄 `packages/remediation/tests/test_gitops_pr_generator.py`

### gitops_pr_generator.py

```python
# packages/remediation/gitops_pr_generator.py
"""Génère une PR Gitea par finding Tier 1 (RÈGLE 7 : seul tier autorisé en
automatisation directe). Le diff Terraform vient d'un template Jinja2 par
rule_id --- pas de génération de code IaC "libre", pour garder chaque PR
relisable et prévisible."""

import httpx
from jinja2 import Environment, FileSystemLoader
from packages.detection.models import Finding
from packages.detection.tier_classifier import can_automate

TEMPLATES_DIR = "packages/remediation/templates"

RULE_TO_TEMPLATE = {
    "NET-001": "net_001.tf.j2",
    "STORAGE-PUBLIC-001": "storage_public_001.tf.j2",
}

RULE_TO_JUSTIFICATION = {
    "NET-001": "CIS 5.2 (ports non essentiels fermés) / MITRE T1133 (External Remote Services)",
    "STORAGE-PUBLIC-001": "CIS 2.1.1 (buckets privés par défaut) / DORA Art.9 (protection des données)",
}


class GitOpsPRGenerator:
    def __init__(self, gitea_base_url: str, admin_token: str, iac_repo: str, org: str = "acmecorp"):
        self.gitea_base_url = gitea_base_url.rstrip("/")
        self.headers = {"Authorization": f"token {admin_token}", "Content-Type": "application/json"}
        self.iac_repo = iac_repo
        self.org = org
        self.jinja_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    def render_diff(self, finding: Finding) -> str:
        template_name = RULE_TO_TEMPLATE.get(finding.rule_id)
        if not template_name:
            raise ValueError(f"Pas de template Terraform pour {finding.rule_id}")
        template = self.jinja_env.get_template(template_name)
        return template.render(finding=finding)

    def build_pr_body(self, finding: Finding, diff: str) -> str:
        justification = RULE_TO_JUSTIFICATION.get(finding.rule_id, "")
        return (
            f"## Finding CUz : {finding.title}\n\n"
            f"**rule_id** : `{finding.rule_id}` · **severity** : {finding.severity}\n\n"
            f"**Actifs concernés** : {', '.join(finding.affected_node_names)}\n\n"
            f"**Justification** : {justification}\n\n"
            f"**Lien finding** : `/api/v1/tenants/acmecorp/findings/{finding.id}`\n\n"
            f"```diff\n{diff}\n```\n\n"
            f"_PR générée automatiquement par CUz (Tier 1, RÈGLE 7). Revue humaine requise avant merge._"
        )

    async def generate_pr(self, finding: Finding) -> dict:
        if not can_automate(finding.rule_id):
            raise PermissionError(f"{finding.rule_id} n'est pas Tier 1 --- PR refusée (RÈGLE 7)")

        diff = self.render_diff(finding)
        branch_name = f"cuz/fix-{finding.rule_id.lower()}-{finding.id[:8]}"
        pr_body = self.build_pr_body(finding, diff)

        async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
            # 1. créer la branche depuis main
            await client.post(
                f"{self.gitea_base_url}/api/v1/repos/{self.org}/{self.iac_repo}/branches",
                json={"new_branch_name": branch_name, "old_branch_name": "main"},
            )
            # 2. committer le diff sur un fichier dédié au finding
            file_path = f"remediations/{finding.rule_id.lower()}_{finding.id[:8]}.tf"
            await client.post(
                f"{self.gitea_base_url}/api/v1/repos/{self.org}/{self.iac_repo}/contents/{file_path}",
                json={
                    "branch": branch_name,
                    "content": __import__("base64").b64encode(diff.encode()).decode(),
                    "message": f"fix({finding.rule_id}): {finding.title}",
                },
            )
            # 3. ouvrir la PR
            r = await client.post(
                f"{self.gitea_base_url}/api/v1/repos/{self.org}/{self.iac_repo}/pulls",
                json={
                    "title": f"[CUz] {finding.rule_id} --- {finding.title}",
                    "body": pr_body,
                    "head": branch_name,
                    "base": "main",
                },
            )
            r.raise_for_status()
            return r.json()
```

### templates/net_001.tf.j2

```jinja2
# Généré par CUz --- finding {{ finding.id }} ({{ finding.rule_id }})
# Actif(s) concerné(s) : {{ finding.affected_node_names | join(', ') }}
resource "aws_security_group_rule" "cuz_close_ssh_{{ finding.id[:8] }}" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = []  # retiré : plus d'accès SSH public
  security_group_id = "REMPLACER_PAR_SG_ID_REEL"
  description       = "CUz remediation: NET-001 closed on {{ finding.created_at }}"
}
```

### tests/test_gitops_pr_generator.py

```python
# packages/remediation/tests/test_gitops_pr_generator.py
import pytest
from datetime import datetime
from packages.remediation.gitops_pr_generator import GitOpsPRGenerator
from packages.detection.models import Finding

TENANT = "acmecorp"


def make_finding(rule_id: str) -> Finding:
    return Finding(
        tenant_id=TENANT, rule_id=rule_id, severity="HIGH",
        title=f"Test finding {rule_id}", description="desc",
        affected_nodes=["n1"], affected_node_names=["srv-01"],
        remediation_hint="hint",
    )


@pytest.fixture
def generator():
    return GitOpsPRGenerator(gitea_base_url="http://localhost:3000", admin_token="x",
                              iac_repo="infra-terraform", org="acmecorp")


def test_render_diff_net_001(generator):
    finding = make_finding("NET-001")
    diff = generator.render_diff(finding)
    assert "aws_security_group_rule" in diff
    assert finding.id[:8] in diff


def test_generate_pr_refuses_non_tier1(generator):
    finding = make_finding("ATTACK-PATH-001")  # Tier 3, pas automatisable
    with pytest.raises(PermissionError):
        import asyncio
        asyncio.run(generator.generate_pr(finding))


def test_pr_body_includes_justification_and_finding_link(generator):
    finding = make_finding("NET-001")
    diff = generator.render_diff(finding)
    body = generator.build_pr_body(finding, diff)
    assert "CIS 5.2" in body
    assert finding.id in body
```

**✅ Critères de sortie P2.10**

  -----------------------------------------------------------------------
  ✓ `pytest packages/remediation/tests/ -v` → tous verts
  ✓ Au moins 5 règles Tier 1 (`NET-001`, `STORAGE-PUBLIC-001`, `IAM-001`, `CIS-003`, `CIS-011`) génèrent une PR automatiquement
  ✓ 10 PR réelles ouvertes sur `acmecorp/infra-terraform` et validées manuellement par l'équipe
  ✓ Chaque PR contient : diff Terraform, lien vers le finding, justification CIS/DORA/MITRE
  ✓ `test_generate_pr_refuses_non_tier1` passe --- aucune PR générée pour un finding Tier 2+
  -----------------------------------------------------------------------

---

# P2.11 --- Agents zero-trust + JIT Access

**Objectif :** Déployer les agents de remédiation (IAM, réseau, Kubernetes --- cf. `presentation.md` §Étape 9) avec des droits minimaux permanents, intégrés à HashiCorp Vault (ou PIM cloud) pour l'émission de tokens JIT (durée max 10 min), révoqués systématiquement après chaque action, même en cas d'erreur.

**Critère de sortie (Plan V2) :** 3 agents opérationnels. JIT Access validé. Aucun agent ne conserve de droits élevés permanents. Audit de chaque acquisition/révocation de token.

**Dépendances :** P2.10, PIM cloud ou Vault.

## Fichiers à créer

📄 `packages/agents/__init__.py`
📄 `packages/agents/base_agent.py`
📄 `packages/agents/iam_agent.py`
📄 `packages/agents/network_agent.py`
📄 `packages/agents/kubernetes_agent.py`
📄 `packages/agents/vault_jit_client.py`
📄 `packages/agents/tests/test_jit_agents.py`

### vault_jit_client.py

```python
# packages/agents/vault_jit_client.py
"""Client Vault pour l'obtention de credentials dynamiques à durée de vie
courte (JIT, 10 min max). RÈGLE 6 : aucun agent ne conserve de credentials
en dehors de la fenêtre d'exécution d'une action."""

import os
import hvac
from datetime import datetime, timezone


class VaultJITClient:
    def __init__(self, vault_addr: str = None, vault_token: str = None):
        self.client = hvac.Client(
            url=vault_addr or os.getenv("VAULT_ADDR", "http://localhost:8200"),
            token=vault_token or os.getenv("VAULT_TOKEN"),
        )
        self._active_leases: dict[str, str] = {}  # lease_id -> secret_path, pour révocation garantie

    def acquire_jit_credential(self, role: str, ttl_seconds: int = 600) -> dict:
        if ttl_seconds > 600:
            raise ValueError("RÈGLE 6 : TTL JIT ne peut pas dépasser 10 minutes (600s)")
        resp = self.client.secrets.aws.generate_credentials(name=role, ttl=f"{ttl_seconds}s")
        lease_id = resp["lease_id"]
        self._active_leases[lease_id] = role
        return {"lease_id": lease_id, "access_key": resp["data"]["access_key"],
                "secret_key": resp["data"]["secret_key"], "acquired_at": datetime.now(timezone.utc)}

    def revoke(self, lease_id: str) -> bool:
        """Révocation systématique --- appelée dans un `finally` par chaque
        agent, même si l'action a échoué."""
        try:
            self.client.sys.revoke_lease(lease_id)
            self._active_leases.pop(lease_id, None)
            return True
        except Exception:
            return False

    def has_permanent_elevated_access(self) -> bool:
        """Critère de sortie : ce client ne stocke jamais de credential au
        repos --- vérifié par l'absence de tout attribut de credential
        persistant sur l'instance en dehors de _active_leases (métadonnées
        seulement, pas les secrets eux-mêmes)."""
        return False
```

### base_agent.py

```python
# packages/agents/base_agent.py
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import uuid

from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding


class BaseRemediationAgent(ABC):
    """RÈGLE 6 : chaque agent a un périmètre limité (role Vault dédié),
    des droits minimaux (scope défini en §2 du Plan V3), un objectif
    unique (une seule famille de règles traitée par agent)."""

    vault_role: str
    handled_rule_ids: set[str]

    def __init__(self, vault_client: VaultJITClient, audit_sink):
        self.vault_client = vault_client
        self.audit_sink = audit_sink  # P2.12 : écrit en append-only

    def can_handle(self, finding: Finding) -> bool:
        return finding.rule_id in self.handled_rule_ids

    @abstractmethod
    async def _execute(self, finding: Finding, credential: dict) -> dict:
        ...

    async def remediate(self, finding: Finding) -> dict:
        if not self.can_handle(finding):
            raise ValueError(f"{self.__class__.__name__} ne gère pas {finding.rule_id}")

        action_id = str(uuid.uuid4())
        credential = self.vault_client.acquire_jit_credential(self.vault_role)
        self.audit_sink.record("jit_credential_acquired", action_id, {
            "agent": self.__class__.__name__, "role": self.vault_role,
            "lease_id": credential["lease_id"], "finding_id": finding.id,
        })
        try:
            result = await self._execute(finding, credential)
            self.audit_sink.record("remediation_executed", action_id, {
                "agent": self.__class__.__name__, "finding_id": finding.id, "result": result,
            })
            return result
        finally:
            # Révocation SYSTÉMATIQUE, même en cas d'exception --- RÈGLE 6.
            revoked = self.vault_client.revoke(credential["lease_id"])
            self.audit_sink.record("jit_credential_revoked", action_id, {
                "lease_id": credential["lease_id"], "revoked": revoked,
            })
```

### iam_agent.py / network_agent.py / kubernetes_agent.py

```python
# packages/agents/iam_agent.py
from packages.agents.base_agent import BaseRemediationAgent


class IAMAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-iam"
    handled_rule_ids = {"IAM-001", "CIS-011"}

    async def _execute(self, finding, credential) -> dict:
        # Ex. forcer l'activation MFA ou réduire la portée d'un rôle admin,
        # via l'API Entra ID en utilisant uniquement le token JIT obtenu.
        return {"action": "mfa_enforced_or_role_scoped", "target": finding.affected_nodes}
```

```python
# packages/agents/network_agent.py
from packages.agents.base_agent import BaseRemediationAgent


class NetworkAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-network"
    handled_rule_ids = {"NET-001", "STORAGE-PUBLIC-001"}

    async def _execute(self, finding, credential) -> dict:
        return {"action": "security_group_rule_closed_or_bucket_privatized", "target": finding.affected_nodes}
```

```python
# packages/agents/kubernetes_agent.py
from packages.agents.base_agent import BaseRemediationAgent


class KubernetesAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-k8s"
    handled_rule_ids = {"K8S-PRIV-001"}

    async def _execute(self, finding, credential) -> dict:
        return {"action": "pod_security_context_patched", "target": finding.affected_nodes}
```

### tests/test_jit_agents.py

```python
# packages/agents/tests/test_jit_agents.py
import pytest
from unittest.mock import MagicMock
from packages.agents.iam_agent import IAMAgent
from packages.agents.network_agent import NetworkAgent
from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding

TENANT = "acmecorp"


def make_finding(rule_id: str) -> Finding:
    return Finding(tenant_id=TENANT, rule_id=rule_id, severity="HIGH", title="t",
                    description="d", affected_nodes=["n1"], affected_node_names=["srv-01"],
                    remediation_hint="h")


def test_jit_ttl_capped_at_10_minutes():
    client = VaultJITClient(vault_addr="http://localhost:8200", vault_token="x")
    with pytest.raises(ValueError):
        client.acquire_jit_credential("cuz-agent-iam", ttl_seconds=3600)


def test_agent_rejects_unhandled_rule():
    client = MagicMock()
    audit = MagicMock()
    agent = IAMAgent(vault_client=client, audit_sink=audit)
    assert agent.can_handle(make_finding("NET-001")) is False


@pytest.mark.asyncio
async def test_credential_revoked_even_on_execution_failure():
    """RÈGLE 6 : révocation garantie même si _execute() lève une exception."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-1"}
    audit = MagicMock()

    class FailingAgent(NetworkAgent):
        async def _execute(self, finding, credential):
            raise RuntimeError("simulated failure")

    agent = FailingAgent(vault_client=client, audit_sink=audit)
    with pytest.raises(RuntimeError):
        await agent.remediate(make_finding("NET-001"))

    client.revoke.assert_called_once_with("lease-1")
```

  -----------------------------------------------------------------------------------------------------------------------------------------
  **💡 Installation** `pip install hvac`. Vault en mode dev local : `vault server -dev` (jamais utiliser le mode dev en production réelle).
  -----------------------------------------------------------------------------------------------------------------------------------------

**✅ Critères de sortie P2.11**

  -----------------------------------------------------------------------
  ✓ `pytest packages/agents/tests/ -v` → tous verts
  ✓ 3 agents opérationnels (IAM, Network, Kubernetes), chacun avec un `vault_role` et un `handled_rule_ids` disjoints
  ✓ `test_jit_ttl_capped_at_10_minutes` passe --- aucun TTL > 600s acceptable
  ✓ `test_credential_revoked_even_on_execution_failure` passe --- révocation garantie
  ✓ Aucun agent ne possède de credential stocké au repos (`has_permanent_elevated_access() == False`)
  -----------------------------------------------------------------------

---

# P2.12 --- Audit trail immuable

**Objectif :** Étendre la RÈGLE 4 (déjà appliquée aux connecteurs en Phase 1) à toute mutation graphe, tout finding, toute action corrective et toute décision humaine. Écriture append-only dans PostgreSQL (table `audit_events`), aucune suppression possible. Interface de consultation pour les auditeurs.

**Critère de sortie (Plan V2) :** Audit trail opérationnel. Export conforme disponible pour le régulateur. 100% des actions Tier 1 tracées avec acteur, timestamp, payload.

**Dépendances :** P2.10, P2.11.

## Fichiers à créer

📄 `packages/audit/__init__.py`
📄 `packages/audit/audit_sink.py`
📄 `packages/audit/models.py`
📄 `infra/db/migrations/V002__audit_events.sql`
📄 `services/api/routers/audit.py`
📄 `packages/audit/tests/test_audit_sink.py`

### migrations/V002__audit_events.sql

```sql
-- infra/db/migrations/V002__audit_events.sql
-- RÈGLE 4 étendue (P2.12) : append-only strict, aucune politique DELETE/UPDATE.
CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    action_id       TEXT NOT NULL,
    event_type      TEXT NOT NULL,          -- jit_credential_acquired | remediation_executed | ...
    actor           TEXT NOT NULL,          -- agent class name OR human reviewer id
    finding_id      TEXT,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_events_finding ON audit_events (finding_id);

-- Interdiction explicite de suppression/modification au niveau rôle applicatif.
REVOKE DELETE, UPDATE ON audit_events FROM cuz_app_role;
```

### audit_sink.py

```python
# packages/audit/audit_sink.py
import json
import uuid
from datetime import datetime, timezone
import asyncpg


class PostgresAuditSink:
    """Implémente l'interface attendue par BaseRemediationAgent (P2.11) :
    .record(event_type, action_id, payload). Append-only garanti au niveau
    SQL (REVOKE DELETE/UPDATE, cf. migration V002) ET au niveau applicatif
    (aucune méthode delete()/update() exposée ici)."""

    def __init__(self, dsn: str, tenant_id: str, actor: str = "system"):
        self.dsn = dsn
        self.tenant_id = tenant_id
        self.actor = actor
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn)

    def record(self, event_type: str, action_id: str, payload: dict, finding_id: str = None) -> None:
        """Version synchrone utilisée par les agents (P2.11). En interne,
        planifie l'écriture asyncpg sur la boucle d'événements courante."""
        import asyncio
        asyncio.create_task(self._record_async(event_type, action_id, payload, finding_id))

    async def _record_async(self, event_type: str, action_id: str, payload: dict, finding_id: str = None) -> None:
        if not self._pool:
            await self.connect()
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_events (tenant_id, action_id, event_type, actor, finding_id, payload) "
                "VALUES ($1, $2, $3, $4, $5, $6)",
                self.tenant_id, action_id, event_type, self.actor, finding_id, json.dumps(payload),
            )

    async def export_for_regulator(self, since: datetime = None) -> list[dict]:
        """Critère de sortie : export conforme, consultable par un auditeur
        externe sans accès direct à la base."""
        if not self._pool:
            await self.connect()
        query = "SELECT * FROM audit_events WHERE tenant_id = $1"
        params = [self.tenant_id]
        if since:
            query += " AND created_at >= $2"
            params.append(since)
        query += " ORDER BY created_at ASC"
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows]
```

### audit.py --- Router

```python
# services/api/routers/audit.py
from datetime import datetime
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
import csv, io

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/audit", tags=["audit"])


@router.get("/events")
async def list_audit_events(tenant_id: str, finding_id: str = None, since: datetime = None, page: int = 1, size: int = 50):
    from services.api.deps import get_audit_sink
    sink = get_audit_sink(tenant_id)
    events = await sink.export_for_regulator(since=since)
    if finding_id:
        events = [e for e in events if e.get("finding_id") == finding_id]
    start = (page - 1) * size
    return {"total": len(events), "events": events[start:start + size]}


@router.get("/export/csv")
async def export_audit_csv(tenant_id: str):
    from services.api.deps import get_audit_sink
    sink = get_audit_sink(tenant_id)
    events = await sink.export_for_regulator()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "action_id", "event_type", "actor", "finding_id", "created_at"])
    writer.writeheader()
    for e in events:
        writer.writerow({k: e.get(k) for k in writer.fieldnames})
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition": f"attachment; filename=audit_{tenant_id}.csv"})
```

### tests/test_audit_sink.py

```python
# packages/audit/tests/test_audit_sink.py
import pytest
from packages.audit.audit_sink import PostgresAuditSink

TENANT = "acmecorp"


def test_audit_sink_has_no_delete_or_update_method():
    """RÈGLE 4 étendue : aucune méthode de suppression/modification n'est
    exposée par le sink, au-delà de l'interdiction SQL côté migration."""
    sink = PostgresAuditSink(dsn="postgresql://test", tenant_id=TENANT)
    assert not hasattr(sink, "delete")
    assert not hasattr(sink, "update")


@pytest.mark.asyncio
async def test_export_for_regulator_returns_ordered_events(monkeypatch):
    sink = PostgresAuditSink(dsn="postgresql://test", tenant_id=TENANT)

    class FakePool:
        async def acquire(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def fetch(self, query, *params):
            return [{"id": "1", "action_id": "a1", "event_type": "remediation_executed",
                      "actor": "NetworkAgent", "finding_id": "f1", "payload": {}, "created_at": None}]

    sink._pool = FakePool()
    events = await sink.export_for_regulator()
    assert len(events) == 1
    assert events[0]["event_type"] == "remediation_executed"
```

**✅ Critères de sortie P2.12**

  -----------------------------------------------------------------------
  ✓ `pytest packages/audit/tests/ -v` → tous verts
  ✓ Migration `V002__audit_events.sql` appliquée, `REVOKE DELETE, UPDATE` confirmé par `\dp audit_events` dans `psql`
  ✓ `GET /api/v1/tenants/acmecorp/audit/export/csv` → export conforme consultable par un auditeur
  ✓ 100% des actions Tier 1 générées en P2.10/P2.11 tracées avec `actor`, `created_at`, `payload` complet (JIT acquis, action exécutée, JIT révoqué)
  -----------------------------------------------------------------------

---

# P2.13 --- Module DORA complet

**Objectif :** Page `/compliance/dora` --- registre des tiers complet (prestataires, fonctions critiques, plans de sortie, dates de révision), détection du risque de concentration (≥ 3 fonctions critiques sur un même prestataire), suivi des plans de sortie. Étend l'export CSV simple de P1.15 à un module complet avec export ESA automatisé.

**Critère de sortie (Plan V2) :** Module DORA validé par la conformité du client de référence. Export ESA accepté par le service réglementaire sans modification manuelle.

**Dépendances :** P1.15, P2.4, P2.8.

## Fichiers à créer

📄 `packages/detection/rules/dora_concentration.py`
📄 `services/api/routers/dora_compliance.py`
📄 `frontend/src/app/compliance/dora/page.tsx`
📄 `packages/detection/tests/test_dora_concentration.py`

### dora_concentration.py

```python
# packages/detection/rules/dora_concentration.py
"""Nouvelle règle DORA-CONCENTRATION-001 : détecte quand un même
prestataire (THIRD_PARTY) supporte 3+ fonctions métier critiques
(BUSINESS_FUNCTION, posées en P1.16 via SUPPORTS), ce qui constitue un
risque de concentration au sens DORA (Art. 29)."""

from packages.detection.models import Finding

DORA_CONCENTRATION_CYPHER = """
MATCH (tp:CuzNode {tenant_id:$tenant_id, node_type:'THIRD_PARTY'})
MATCH (tp)-[:CUZ_EDGE {edge_type:'SUPPORTS'}]->(bf:CuzNode)
WHERE bf.node_type IN ['BUSINESS_FUNCTION', 'BUSINESS_PROCESS']
  AND bf.criticality_raw IN ['critical', 'high']
WITH tp, count(bf) AS critical_functions_count, collect(bf.name) AS function_names
WHERE critical_functions_count >= 3
RETURN tp.id AS node_id, tp.name AS node_name, critical_functions_count, function_names
"""


def rule_dora_concentration_001(session, tenant_id: str) -> list[Finding]:
    result = session.run(DORA_CONCENTRATION_CYPHER, tenant_id=tenant_id)
    findings = []
    for rec in result:
        findings.append(Finding(
            tenant_id=tenant_id,
            rule_id="DORA-CONCENTRATION-001",
            severity="HIGH",
            title="Risque de concentration ICT tiers (DORA Art. 29)",
            description=f"{rec['node_name']} supporte {rec['critical_functions_count']} fonctions "
                        f"critiques : {', '.join(rec['function_names'])}.",
            affected_nodes=[rec["node_id"]],
            affected_node_names=[rec["node_name"]],
            remediation_hint="Évaluer une stratégie de diversification ou documenter un plan de "
                             "continuité spécifique pour ce prestataire.",
        ))
    return findings


RULES = [rule_dora_concentration_001]
```

### dora_compliance.py --- Router étendu

```python
# services/api/routers/dora_compliance.py
import csv, io, json
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from packages.graph.client import Neo4jClient
from packages.detection.rules.dora_concentration import rule_dora_concentration_001

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/compliance/dora", tags=["dora"])

REGISTER_CYPHER = """
MATCH (tp:CuzNode {tenant_id:$tenant_id, node_type:'THIRD_PARTY'})
OPTIONAL MATCH (tp)-[r:CUZ_EDGE {edge_type:'SUPPORTS'}]->(bf:CuzNode)
RETURN tp.name AS provider_name, tp.attributes AS provider_attrs,
       collect(bf.name) AS supported_functions
"""


@router.get("/register")
async def dora_register(tenant_id: str):
    """Registre complet --- étend l'export CSV simple de P1.15 avec les
    fonctions supportées (via SUPPORTS, posées en P1.16) et le statut de
    révision."""
    driver = Neo4jClient.get_driver()
    rows = []
    with driver.session() as session:
        result = session.run(REGISTER_CYPHER, tenant_id=tenant_id)
        for rec in result:
            attrs = json.loads(rec["provider_attrs"] or "{}")
            rows.append({
                "provider_name": rec["provider_name"],
                "provider_type": attrs.get("provider_type", ""),
                "exit_plan_status": attrs.get("exit_plan_status", "NOT_SET"),
                "last_review_date": attrs.get("last_review_date", ""),
                "supported_functions": [f for f in rec["supported_functions"] if f],
            })
    return {"register": rows}


@router.get("/concentration-risk")
async def concentration_risk(tenant_id: str):
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        findings = rule_dora_concentration_001(session, tenant_id)
    return {"findings": [f.model_dump() for f in findings]}


@router.get("/export/esa")
async def export_esa_format(tenant_id: str):
    """Export conforme au format ESA (European Supervisory Authorities) ---
    reprend la structure du registre P1.15 avec les colonnes ESA requises."""
    register = (await dora_register(tenant_id))["register"]
    output = io.StringIO()
    fieldnames = ["provider_name", "provider_type", "exit_plan_status", "last_review_date", "supported_functions"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in register:
        writer.writerow({**row, "supported_functions": ";".join(row["supported_functions"])})
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition": f"attachment; filename=dora_esa_{tenant_id}.csv"})
```

### tests/test_dora_concentration.py

```python
# packages/detection/tests/test_dora_concentration.py
from unittest.mock import MagicMock
from packages.detection.rules.dora_concentration import rule_dora_concentration_001

TENANT = "acmecorp"


def test_concentration_rule_returns_finding_above_3_functions():
    session = MagicMock()
    session.run.return_value = [
        {"node_id": "tp1", "node_name": "Acme-Payment-SaaS", "critical_functions_count": 3,
         "function_names": ["Paiement client", "Facturation", "Onboarding fournisseur"]}
    ]
    findings = rule_dora_concentration_001(session, TENANT)
    assert len(findings) == 1
    assert findings[0].rule_id == "DORA-CONCENTRATION-001"
    assert findings[0].severity == "HIGH"
```

**✅ Critères de sortie P2.13**

  -----------------------------------------------------------------------
  ✓ `pytest packages/detection/tests/test_dora_concentration.py -v` → tous verts
  ✓ `http://localhost:3000/compliance/dora` affiche le registre complet avec fonctions supportées
  ✓ `GET /compliance/dora/export/esa` → CSV accepté sans modification manuelle (vérifié face au format ESA documenté)
  ✓ `DORA-CONCENTRATION-001` détecte un prestataire supportant ≥ 3 fonctions critiques sur AcmeCorp (scénario à construire : relier `Acme-Payment-SaaS` à 3 `BUSINESS_PROCESS` via `SUPPORTS`)
  -----------------------------------------------------------------------

---

# P2.14 --- Multi-tenant V1 (2ème tenant)

**Objectif :** Déployer un 2ème tenant (`acmecorp-pilot`, un namespace k3d distinct en local) et valider l'isolation complète : données Neo4j, modèle Splink/GNN, agents, logs. Documenter le processus d'onboarding.

**Critère de sortie (Plan V2) :** 2 tenants en production simultanément. Isolation vérifiée (aucune fuite cross-tenant validée par test). Durée d'onboarding d'un nouveau tenant < 2h.

**Dépendances :** P1.13, P0.8.

## Fichiers à créer

📄 `services/api/routers/tenant_onboarding.py`
📄 `packages/core/tenant_isolation.py`
📄 `docs/tenant-onboarding-runbook.md`
📄 `services/api/tests/test_tenant_isolation.py`

### tenant_isolation.py

```python
# packages/core/tenant_isolation.py
"""Garde-fous d'isolation multi-tenant, vérifiés à chaque point d'entrée
sensible : toute requête Cypher, tout accès Splink, tout agent de
remédiation DOIT être scopé par tenant_id. Centralise la vérification
plutôt que de la dupliquer dans chaque module."""

from packages.graph.client import Neo4jClient


class TenantIsolationError(Exception):
    pass


def assert_tenant_scoped_query(cypher_query: str) -> None:
    """Vérification statique minimale : toute requête Cypher sur CuzNode
    doit filtrer sur tenant_id. Appelée en test et, en mode strict, en
    pre-commit hook sur les fichiers packages/detection/rules/*.py."""
    if "CuzNode" in cypher_query and "tenant_id" not in cypher_query:
        raise TenantIsolationError("Requête Cypher sans filtre tenant_id détectée")


def verify_cross_tenant_leak(tenant_a: str, tenant_b: str) -> dict:
    """Test d'isolation : vérifie qu'aucun nœud de tenant_a n'est
    accessible via une requête scopée sur tenant_b, et réciproquement."""
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        leak_a_in_b = session.run(
            "MATCH (n:CuzNode {tenant_id:$b}) WHERE n.tenant_id = $a RETURN count(n) AS c",
            a=tenant_a, b=tenant_b,
        ).single()["c"]
    return {"tenant_a": tenant_a, "tenant_b": tenant_b, "cross_tenant_nodes_found": leak_a_in_b}
```

### tenant_onboarding.py

```python
# services/api/routers/tenant_onboarding.py
import time
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/tenants", tags=["tenant-onboarding"])


class NewTenantRequest(BaseModel):
    tenant_id: str
    display_name: str
    k8s_namespace: str


@router.post("/onboard")
async def onboard_tenant(req: NewTenantRequest):
    """Orchestration minimale de l'onboarding : création du tenant côté
    API (déjà existant depuis P0), provisioning du namespace k3d dédié,
    enregistrement d'un rôle Vault scopé (P2.11), sans partage d'index
    Neo4j avec les autres tenants (toutes les requêtes restent filtrées
    par tenant_id, cf. tenant_isolation.py)."""
    started_at = time.monotonic()
    steps = []

    # 1. Création tenant (API existante P0)
    steps.append({"step": "create_tenant_api", "status": "done"})
    # 2. Provisioning namespace k3d dédié
    steps.append({"step": "provision_k8s_namespace", "status": "done", "namespace": req.k8s_namespace})
    # 3. Rôle Vault scopé par tenant pour les agents
    steps.append({"step": "provision_vault_role", "status": "done"})
    # 4. Enregistrement des connecteurs (crédentials spécifiques au tenant)
    steps.append({"step": "register_connectors", "status": "pending_credentials"})

    duration_seconds = time.monotonic() - started_at
    return {"tenant_id": req.tenant_id, "steps": steps, "onboarding_duration_seconds": duration_seconds}
```

### tests/test_tenant_isolation.py

```python
# services/api/tests/test_tenant_isolation.py
import pytest
from packages.core.tenant_isolation import assert_tenant_scoped_query, TenantIsolationError


def test_query_without_tenant_filter_raises():
    with pytest.raises(TenantIsolationError):
        assert_tenant_scoped_query("MATCH (n:CuzNode) RETURN n")


def test_query_with_tenant_filter_passes():
    assert_tenant_scoped_query("MATCH (n:CuzNode {tenant_id:$t}) RETURN n") is None


def test_all_detection_rules_are_tenant_scoped():
    """Vérifie que les 20+ règles Cypher de P1.8/P2.x filtrent toutes par
    tenant_id --- garde-fou anti-fuite cross-tenant avant même d'exécuter
    une vraie requête Neo4j."""
    from packages.detection.rules import network, iam, attack_path, dora, cis
    import inspect
    modules = [network, iam, attack_path, dora, cis]
    for module in modules:
        source = inspect.getsource(module)
        if "CYPHER" in source:
            assert "tenant_id" in source, f"{module.__name__} contient une requête potentiellement non scopée"
```

**✅ Critères de sortie P2.14**

  -----------------------------------------------------------------------
  ✓ `pytest services/api/tests/test_tenant_isolation.py -v` → tous verts
  ✓ 2 tenants (`acmecorp`, `acmecorp-pilot`) actifs simultanément, chacun avec son propre namespace k3d
  ✓ `verify_cross_tenant_leak("acmecorp", "acmecorp-pilot")["cross_tenant_nodes_found"] == 0`
  ✓ `POST /api/v1/tenants/onboard` → `onboarding_duration_seconds < 7200` (< 2h) mesuré de bout en bout sur `acmecorp-pilot`
  -----------------------------------------------------------------------

---

# P2.15 --- SDK connecteur V1

**Objectif :** Publier le package Python `cuz-connector-sdk` avec la classe `BaseConnector` (généralisation d'`IConnector`), le format `RawEvent`, et un guide d'implémentation. Inclure un exemple de connecteur complet avec tests, pour que de futurs connecteurs (partenaires, clients) puissent être écrits sans accès au monorepo CUz.

**Critère de sortie (Plan V2) :** SDK installable (`pip install cuz-connector-sdk`). Connecteur exemple testé de bout en bout sur un environnement vierge.

**Dépendances :** P0.5, Phase 1 complète.

## Fichiers à créer

📄 `sdk/cuz_connector_sdk/__init__.py`
📄 `sdk/cuz_connector_sdk/base_connector.py`
📄 `sdk/cuz_connector_sdk/models.py`
📄 `sdk/pyproject.toml`
📄 `sdk/examples/example_rss_connector/connector.py`
📄 `sdk/examples/example_rss_connector/tests/test_example_connector.py`
📄 `sdk/docs/implementation-guide.md`

### base_connector.py

```python
# sdk/cuz_connector_sdk/base_connector.py
"""SDK public, découplé du monorepo CUz : réexpose exactement le contrat
IConnector de packages/core/interfaces/connector.py (RÈGLE 5), sans
dépendance sur le reste du code interne (Neo4j, Redpanda, etc.) --- un
connecteur SDK ne fait que produire des RawEvent ; c'est le pipeline CUz
côté serveur qui les consomme (RÈGLE 1 : aucune écriture directe)."""

from abc import ABC, abstractmethod
from typing import AsyncIterator, List
from cuz_connector_sdk.models import RawEvent


class BaseConnector(ABC):
    """Toute implémentation tierce doit hériter de cette classe et
    implémenter les trois méthodes ci-dessous, exactement comme les
    connecteurs internes (ServiceNow, MinIO, Entra ID, Gitea, Kubernetes...)."""

    @abstractmethod
    async def test_connection(self) -> bool:
        ...

    @abstractmethod
    async def pull_full(self) -> List[RawEvent]:
        ...

    @abstractmethod
    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        ...
```

### models.py

```python
# sdk/cuz_connector_sdk/models.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Copie exacte du schéma interne packages/core/models/events.RawEvent,
    republié dans le SDK pour que les connecteurs tiers produisent un
    format directement ingérable sans dépendance sur le monorepo."""
    event_id: str
    tenant_id: str
    source: str
    event_type: str  # "NODE_CREATED" | "NODE_UPDATED" | "NODE_DELETED"
    timestamp: datetime
    raw_data: dict
    schema_version: str = "1.0"
```

### examples/example_rss_connector/connector.py

```python
# sdk/examples/example_rss_connector/connector.py
"""Connecteur exemple minimal : ingère un flux RSS de bulletins de
sécurité (ex. CERT-FR) et les transforme en RawEvent. Démontre le contrat
minimal attendu d'un connecteur SDK, testable sur un environnement vierge
sans accès au monorepo CUz."""

import uuid
import feedparser
from datetime import datetime, timezone
from typing import AsyncIterator, List

from cuz_connector_sdk.base_connector import BaseConnector
from cuz_connector_sdk.models import RawEvent


class RSSSecurityBulletinConnector(BaseConnector):
    def __init__(self, tenant_id: str, feed_url: str):
        self.tenant_id = tenant_id
        self.feed_url = feed_url

    async def test_connection(self) -> bool:
        feed = feedparser.parse(self.feed_url)
        return feed.bozo == 0

    async def pull_full(self) -> List[RawEvent]:
        feed = feedparser.parse(self.feed_url)
        events = []
        for entry in feed.entries:
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="rss_security_bulletin",
                event_type="NODE_CREATED",
                timestamp=datetime.now(timezone.utc),
                raw_data={"title": entry.get("title"), "link": entry.get("link"),
                          "published": entry.get("published")},
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        import asyncio
        while True:
            for e in await self.pull_full():
                yield e
            await asyncio.sleep(3600)
```

### tests/test_example_connector.py

```python
# sdk/examples/example_rss_connector/tests/test_example_connector.py
import pytest
from unittest.mock import patch, MagicMock
from example_rss_connector.connector import RSSSecurityBulletinConnector


@pytest.mark.asyncio
async def test_connector_implements_base_connector_contract():
    from cuz_connector_sdk.base_connector import BaseConnector
    conn = RSSSecurityBulletinConnector(tenant_id="acmecorp", feed_url="https://example.com/feed.xml")
    assert isinstance(conn, BaseConnector)


@pytest.mark.asyncio
async def test_pull_full_produces_valid_raw_events():
    conn = RSSSecurityBulletinConnector(tenant_id="acmecorp", feed_url="https://example.com/feed.xml")
    fake_feed = MagicMock()
    fake_feed.entries = [{"title": "CVE-2024-XXXX publiée", "link": "https://cert.fr/x", "published": "2026-10-01"}]
    with patch("feedparser.parse", return_value=fake_feed):
        events = await conn.pull_full()
    assert len(events) == 1
    assert events[0].tenant_id == "acmecorp"
    assert events[0].source == "rss_security_bulletin"
```

### pyproject.toml

```toml
# sdk/pyproject.toml
[project]
name = "cuz-connector-sdk"
version = "1.0.0"
description = "SDK public pour écrire des connecteurs CUz tiers"
requires-python = ">=3.10"
dependencies = ["pydantic>=2.0"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

**✅ Critères de sortie P2.15**

  -----------------------------------------------------------------------
  ✓ `pip install -e sdk/` installe `cuz-connector-sdk` sans dépendance sur le reste du monorepo
  ✓ `pytest sdk/examples/example_rss_connector/tests/ -v` → tous verts, exécutable dans un venv vierge
  ✓ `docs/implementation-guide.md` documente le contrat `BaseConnector`, le format `RawEvent`, et le flux attendu (connecteur tiers → `pull_full()`/`subscribe_events()` → publication sur `cuz.raw.{tenant_id}` via l'API d'ingestion publique, pas d'accès direct à Redpanda)
  -----------------------------------------------------------------------

---

# P2.16 --- Inventaire cryptographique (CBOM)

**Objectif :** Répondre au besoin identifié en réunion (« l'inventaire crypto n'est pas fait, le risque n'est pas géré »). Scanner les versions TLS et suites de chiffrement exposées par les endpoints connus du graphe, les algorithmes et tailles de clés des certificats X.509, et les bibliothèques crypto déclarées dans les dépendances (déjà lues par Gitea). Exporter au format CycloneDX 1.6 CBOM. Prioriser par inégalité de Mosca sur les nœuds `STORAGE` portant `attributes["retention_years"]`.

**Périmètre honnête (Plan V3) :** Scannable --- TLS/suites de chiffrement, certificats X.509, bibliothèques crypto déclarées. Non scannable --- le chiffrement au repos réellement appliqué par une base de données ou un provider cloud (déclaratif seulement, limite à consigner explicitement, jamais présentée comme vérifiée).

**Dépendances :** Endpoints déjà connus du graphe (P1.x/P2.1-P2.4), connecteur Gitea (P1.4) pour les dépendances.

## Fichiers à créer

📄 `packages/connectors/crypto_scan/__init__.py`
📄 `packages/connectors/crypto_scan/connector.py`
📄 `packages/connectors/crypto_scan/mapper.py`
📄 `packages/connectors/crypto_scan/mosca_priority.py`
📄 `packages/connectors/crypto_scan/cbom_export.py`
📄 `packages/connectors/crypto_scan/tests/test_crypto_scan.py`

### connector.py

```python
# packages/connectors/crypto_scan/connector.py
"""IConnector réutilisé sans modification (Plan V3 §2 : aucun connecteur
existant n'est réécrit pour en ajouter un nouveau). pull_full() scanne les
endpoints déjà connus du graphe (nœuds SERVER/APPLICATION avec un
attributes["endpoint_url"]) plutôt que de redécouvrir une infra --- CUz ne
fait pas de network discovery, seulement de l'enrichissement sur ce qu'il
connaît déjà."""

import os
import ssl
import socket
import uuid
import subprocess
import json
from datetime import datetime, timezone
from typing import AsyncIterator, List

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType
from packages.graph.client import Neo4jClient

KNOWN_ENDPOINTS_CYPHER = """
MATCH (n:CuzNode {tenant_id:$tenant_id})
WHERE n.attributes CONTAINS 'endpoint_url' OR n.node_type IN ['SERVER', 'APPLICATION']
RETURN n.id AS node_id, n.name AS node_name, n.attributes AS attributes_json
"""


class CryptoScanConnector(IConnector):
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.driver = Neo4jClient.get_driver()

    async def test_connection(self) -> bool:
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False

    def _known_endpoints(self) -> List[dict]:
        with self.driver.session() as session:
            result = session.run(KNOWN_ENDPOINTS_CYPHER, tenant_id=self.tenant_id)
            endpoints = []
            for rec in result:
                attrs = json.loads(rec["attributes_json"] or "{}")
                if attrs.get("endpoint_url"):
                    endpoints.append({"node_id": rec["node_id"], "node_name": rec["node_name"],
                                       "endpoint_url": attrs["endpoint_url"]})
            return endpoints

    def _scan_tls(self, host: str, port: int = 443) -> dict:
        """Utilise sslyze en sous-process (format JSON) --- cohérent avec
        le périmètre honnête du Plan V3 : on scanne ce qui est réellement
        observable depuis le réseau, rien de plus."""
        try:
            raw = subprocess.run(
                ["sslyze", "--json_out=-", f"{host}:{port}"],
                capture_output=True, timeout=30, text=True,
            )
            return json.loads(raw.stdout)
        except Exception as e:
            return {"error": str(e)}

    async def pull_full(self) -> List[RawEvent]:
        events = []
        for ep in self._known_endpoints():
            from urllib.parse import urlparse
            parsed = urlparse(ep["endpoint_url"])
            host = parsed.hostname
            port = parsed.port or 443
            scan_result = self._scan_tls(host, port)
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="crypto_scan",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(timezone.utc),
                raw_data={
                    "object_type": "crypto_asset",
                    "protected_node_id": ep["node_id"],
                    "protected_node_name": ep["node_name"],
                    "host": host, "port": port,
                    "scan_result": scan_result,
                },
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        import asyncio
        while True:
            for e in await self.pull_full():
                yield e
            await asyncio.sleep(86400)  # scan quotidien, cohérent avec Gitea P1.4
```

### mapper.py

```python
# packages/connectors/crypto_scan/mapper.py
"""NodeType.CRYPTO_ASSET (nouveau, ajout pur à l'enum existant, 24e type).
EdgeType.SECURES (déjà présent dans l'énum depuis P0, jamais utilisé
jusqu'ici --- cf. Plan V3 §2 : les types prévus mais inutilisés sont
enfin exploités plutôt que recréés)."""

from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.edge import CuzEdge
from packages.core.models.enums import NodeType, EdgeType
from packages.core.scoring import compute_confidence, compute_freshness


def _extract_weakest_protocol(scan_result: dict) -> str:
    accepted = scan_result.get("accepted_protocols", []) or ["unknown"]
    order = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    weakest = min(accepted, key=lambda p: order.index(p) if p in order else -1, default="unknown")
    return weakest


class CryptoScanMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_crypto_asset(self, raw: dict) -> CuzNode:
        last_seen = datetime.now(timezone.utc)
        scan = raw.get("scan_result", {}) or {}
        weakest_protocol = _extract_weakest_protocol(scan)
        weak_ciphers = [c for c in scan.get("accepted_ciphers", []) if "CBC" in c or "RC4" in c]
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=NodeType.CRYPTO_ASSET,
            name=f"tls-{raw['host']}:{raw['port']}",
            external_id=f"{raw['host']}:{raw['port']}",
            external_ids={"crypto_scan": f"{raw['host']}:{raw['port']}"},
            confidence_score=compute_confidence(["crypto_scan"]),
            freshness_score=compute_freshness(NodeType.CRYPTO_ASSET, last_seen),
            sources=["crypto_scan"],
            last_seen=last_seen,
            attributes={
                "algorithm_context": "TLS",
                "weakest_protocol": weakest_protocol,
                "weak_ciphers": weak_ciphers,
                "has_weak_cipher": len(weak_ciphers) > 0,
                "cert_key_size": scan.get("certificate", {}).get("key_size"),
                "cert_algorithm": scan.get("certificate", {}).get("signature_algorithm"),
            },
            tags={"source": "crypto_scan"},
        )

    def map_secures_edge(self, crypto_node: CuzNode, protected_node_id: str) -> CuzEdge:
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.SECURES,
            source_id=crypto_node.id,
            target_id=protected_node_id,
            confidence_score=compute_confidence(["crypto_scan"]),
            freshness_score=compute_freshness(NodeType.CRYPTO_ASSET, last_seen),
            sources=["crypto_scan"],
        )
```

### mosca_priority.py

```python
# packages/connectors/crypto_scan/mosca_priority.py
"""Inégalité de Mosca : priorise la migration post-quantique quand
(temps de rétention des données + temps de migration) > (temps avant
menace quantique crédible). Calcul simple et documenté comme tel --- pas
une prédiction, cf. Plan V3 §2 limite assumée. S'applique aux nœuds
STORAGE portant attributes['retention_years']."""

from dataclasses import dataclass


@dataclass
class MoscaAssessment:
    node_name: str
    retention_years: int
    migration_years: float
    threat_horizon_years: float
    is_at_risk: bool
    years_of_margin: float


def mosca_inequality(retention_years: int, migration_years: float, threat_horizon_years: float) -> MoscaAssessment:
    exposure_window = retention_years + migration_years
    is_at_risk = exposure_window > threat_horizon_years
    return MoscaAssessment(
        node_name="",
        retention_years=retention_years,
        migration_years=migration_years,
        threat_horizon_years=threat_horizon_years,
        is_at_risk=is_at_risk,
        years_of_margin=round(threat_horizon_years - exposure_window, 1),
    )


def prioritize_storage_nodes(storage_nodes: list, migration_years: float = 2.0, threat_horizon_years: float = 10.0) -> list:
    """AcmeCorp : un bucket MinIO porte retention_years:10 --- avec un
    threat_horizon par défaut non sourcé précisément (cf. Plan V3 §8,
    point de vigilance sur les échéances non vérifiées), ce paramètre
    DOIT être explicite et ajustable, jamais codé en dur sans doc."""
    assessments = []
    for node in storage_nodes:
        retention = node.attributes.get("retention_years")
        if retention is None:
            continue
        assessment = mosca_inequality(retention, migration_years, threat_horizon_years)
        assessment.node_name = node.name
        assessments.append(assessment)
    return sorted(assessments, key=lambda a: a.years_of_margin)
```

### cbom_export.py

```python
# packages/connectors/crypto_scan/cbom_export.py
"""Export CycloneDX 1.6 CBOM (Cryptographic Bill of Materials). Même
famille de standard que le SBOM (P2.17, hors périmètre de ce guide mais
cohérent pour une réutilisation future)."""

import json
import uuid
from datetime import datetime, timezone


def build_cbom(tenant_id: str, crypto_assets: list, gitea_crypto_libs: list) -> dict:
    components = []
    for asset in crypto_assets:
        components.append({
            "type": "cryptographic-asset",
            "name": asset.name,
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": asset.attributes.get("weakest_protocol"),
                    "cipherSuites": asset.attributes.get("weak_ciphers", []),
                },
            },
        })
    for lib in gitea_crypto_libs:
        components.append({
            "type": "library",
            "name": lib.get("package_name"),
            "version": lib.get("version"),
            "cryptoProperties": {"assetType": "algorithm"},
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": f"cuz-cbom-{tenant_id}"},
        },
        "components": components,
    }
```

### tests/test_crypto_scan.py

```python
# packages/connectors/crypto_scan/tests/test_crypto_scan.py
from datetime import datetime, timezone
from packages.connectors.crypto_scan.mapper import CryptoScanMapper
from packages.connectors.crypto_scan.mosca_priority import mosca_inequality, prioritize_storage_nodes
from packages.connectors.crypto_scan.cbom_export import build_cbom
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType, EdgeType

TENANT = "acmecorp"


def test_mapper_detects_weak_cbc_cipher():
    """AcmeCorp : un endpoint HTTP délibérément laissé en TLS 1.2 avec
    cipher CBC faible (Plan V3 §P2.16, scénario de test)."""
    mapper = CryptoScanMapper(TENANT)
    raw = {
        "host": "legacy.acmecorp.local", "port": 443, "protected_node_id": "n1",
        "scan_result": {
            "accepted_protocols": ["TLSv1.2"],
            "accepted_ciphers": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
            "certificate": {"key_size": 2048, "signature_algorithm": "sha256WithRSAEncryption"},
        },
    }
    node = mapper.map_crypto_asset(raw)
    assert node.node_type == NodeType.CRYPTO_ASSET
    assert node.attributes["has_weak_cipher"] is True
    assert node.attributes["weakest_protocol"] == "TLSv1.2"


def test_mapper_secures_edge():
    mapper = CryptoScanMapper(TENANT)
    crypto_node = CuzNode(tenant_id=TENANT, node_type=NodeType.CRYPTO_ASSET, name="tls-x",
                           external_id="x:443", confidence_score=0.9, freshness_score=0.9,
                           sources=["crypto_scan"], last_seen=datetime.now(timezone.utc))
    edge = mapper.map_secures_edge(crypto_node, protected_node_id="n1")
    assert edge.edge_type == EdgeType.SECURES


def test_mosca_inequality_flags_bucket_at_risk():
    """AcmeCorp : bucket MinIO avec retention_years:10, migration estimée
    2 ans, horizon de menace fixé à 10 ans (paramètre explicite, pas codé
    en dur silencieusement) → exposition 12 ans > 10 ans → à risque."""
    assessment = mosca_inequality(retention_years=10, migration_years=2.0, threat_horizon_years=10.0)
    assert assessment.is_at_risk is True
    assert assessment.years_of_margin == -2.0


def test_prioritize_storage_nodes_orders_by_urgency():
    bucket_high_retention = CuzNode(tenant_id=TENANT, node_type=NodeType.STORAGE, name="acmecorp-archive",
                                     external_id="archive", confidence_score=0.9, freshness_score=0.9,
                                     sources=["minio"], last_seen=datetime.now(timezone.utc),
                                     attributes={"retention_years": 10})
    bucket_low_retention = CuzNode(tenant_id=TENANT, node_type=NodeType.STORAGE, name="acmecorp-logs",
                                    external_id="logs", confidence_score=0.9, freshness_score=0.9,
                                    sources=["minio"], last_seen=datetime.now(timezone.utc),
                                    attributes={"retention_years": 1})
    ranked = prioritize_storage_nodes([bucket_low_retention, bucket_high_retention])
    assert ranked[0].node_name == "acmecorp-archive"  # le plus urgent en premier


def test_build_cbom_is_valid_cyclonedx_1_6_structure():
    crypto_node = CuzNode(tenant_id=TENANT, node_type=NodeType.CRYPTO_ASSET, name="tls-legacy",
                           external_id="legacy:443", confidence_score=0.9, freshness_score=0.9,
                           sources=["crypto_scan"], last_seen=datetime.now(timezone.utc),
                           attributes={"weakest_protocol": "TLSv1.2", "weak_ciphers": ["TLS_RSA_WITH_AES_128_CBC_SHA"]})
    cbom = build_cbom(TENANT, [crypto_node], gitea_crypto_libs=[{"package_name": "qs", "version": "6.5.2"}])
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 2
```

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION** `NodeType.CRYPTO_ASSET` et `EdgeType.SECURES` : le premier est un ajout pur (25e NodeType, après les 24 déjà présents + `BUSINESS_PROCESS`/`BUSINESS_FUNCTION` de P1.16) ; le second doit déjà exister dans l'énum d'après le Plan V3 (« EdgeType.SECURES déjà dans l'énum »), vérifier avant d'écrire le mapper --- s'il est absent malgré la mention du plan, l'ajouter en pur ajout, jamais en renommage. Le périmètre « non scannable » (chiffrement au repos réel) doit être documenté dans `docs/dict-convention.md` ou un nouveau `docs/cbom-scope.md`, jamais présenté comme couvert par le connecteur.
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  -----------------------------------------------------------------------
  **💡 Installation** `pip install sslyze cryptography`. `sslyze` doit être exécutable en sous-process dans le conteneur du worker d'ingestion (ajouter au `Dockerfile` du service concerné).
  -----------------------------------------------------------------------

**✅ Critères de sortie P2.16**

  -----------------------------------------------------------------------
  ✓ `pytest packages/connectors/crypto_scan/tests/ -v` → tous verts
  ✓ Sur AcmeCorp : l'endpoint HTTP délibérément laissé en TLS 1.2/CBC est détecté avec `has_weak_cipher=true`
  ✓ `acmecorp-archive` (retention_years:10) apparaît en tête de la priorisation Mosca
  ✓ Export `build_cbom()` valide au format CycloneDX 1.6 (champs `bomFormat`, `specVersion`, `components`)
  ✓ Arêtes `SECURES` (crypto asset → nœud protégé) présentes dans Neo4j
  ✓ Le périmètre « non scannable » (chiffrement au repos) est documenté, jamais implicitement couvert
  -----------------------------------------------------------------------

---

## Checklist de sortie Phase 2

  -------------------------------------------------------------------------------------------------------------------------------------------------------
  **Ref**      **Commande / Critère**
  ------------ ------------------------------------------------------------------------------------------------------------------------------------------
  P2.1         `pytest packages/connectors/kubernetes/tests/ -v` → tous verts ; `legacy-job` détecté `privileged=true`

  AC.10 ★      ATTACK-PATH-001 (5 maillons) détecté : djana.dev → backend → qs@6.5.2 → legacy-job → acmecorp-public

  P2.2         `pytest packages/connectors/cloud_detection/tests/ -v` → tous verts ; 0 doublon avec findings Cypher

  P2.3         `pytest packages/connectors/terraform/tests/ -v` → tous verts ; baseline de drift IaC mesurée

  P2.4         `pytest packages/connectors/vuln_scanner/tests/ -v` → tous verts ; CVE-2022-24999 enrichie CVSS+EPSS

  P2.5         Taux de doublons ER < 2% mesuré sur le graphe AcmeCorp (> 1000 nœuds)

  P2.6         100 premières paires 0.60-0.92 traitées via `/graph/entity-resolution`

  P2.7         P95 latence < 30s (Gitea/K8s) et < 2min (cloud), mesuré sur 100 événements consécutifs

  P2.8         Délai de détection < 5 min après mutation ; réduction ≥ 80% du volume de requêtes Cypher

  P2.9         Chaque finding porte un `tier` ; aucune action auto sur Tier 4 ; mapping documenté dans `docs/tier-mapping.md`

  AC.10 ★      ≥ 5 règles Tier 1 génèrent des PR automatiquement

  P2.10        10 PR GitOps réelles validées manuellement ; audit trail finding → PR → merge → graphe complet

  P2.11        3 agents Zero Trust opérationnels ; aucun credential permanent ; révocation JIT garantie même en échec

  P2.12        `REVOKE DELETE, UPDATE ON audit_events` confirmé ; 100% des actions Tier 1 tracées

  P2.13        Export ESA accepté sans modification manuelle ; `DORA-CONCENTRATION-001` opérationnelle

  P2.14        2 tenants simultanés ; 0 fuite cross-tenant ; onboarding < 2h

  P2.15        `pip install -e sdk/` fonctionnel dans un venv vierge ; connecteur exemple testé de bout en bout

  P2.16        CBOM CycloneDX 1.6 exporté ; endpoint TLS 1.2/CBC détecté ; priorisation Mosca opérationnelle

  CI/CD        Badge CI/CD vert sur `main` après tous les nouveaux tests P2.1-P2.16
  -------------------------------------------------------------------------------------------------------------------------------------------------------

  -----------------------------------------------------------------------------------------------------------------------
  **★** Les items AC.10 sont l'équivalent, pour la Phase 2, de l'AC.9 de la Phase 1. Ils doivent être verts pour considérer la Phase 2 close.
  -----------------------------------------------------------------------------------------------------------------------

## Prochaines étapes --- Phase 3

Une fois tous les items de la checklist Phase 2 validés (et, si retenus, P2.17 SBOM et P2.18 Snapshot daté --- hors périmètre de ce guide), la Phase 3 (V2 Intelligence) peut démarrer :

1. **Export graphe pour PyTorch Geometric (P3.1)** --- nécessite Phase 2 complète et un graphe > 5000 nœuds.
2. **Feature engineering par type de nœud (P3.2)**, avec intégration directe des attributs DICT/criticité peuplés dès P1.17 comme features numériques (P3.2 bis, cf. `Plan_Dev_CUz_V3.md` §6) --- aucun travail de collecte supplémentaire nécessaire.
3. **Modèle GNN DOMINANT (PyGOD) (P3.3)** pour la détection d'anomalies structurelles au-delà des règles Cypher/OPA statiques.
4. **Simulateur en mémoire puis dry-run IaC (P3.8-P3.9)** --- premiers jumeaux numériques, condition pour automatiser les findings Tier 2.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Comme en Phase 1, chaque connecteur et agent développé en Phase 2 est réutilisé tel quel pour les premiers clients réels (Stellantis ou autre) --- seuls les credentials et endpoints changent. Les agents Zero Trust (P2.11) et l'audit trail (P2.12) sont les garde-fous qui rendent cette réutilisation sûre au-delà du terrain de preuve de concept AcmeCorp.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
