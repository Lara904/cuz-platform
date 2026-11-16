# packages/agents/kubernetes_agent.py
"""RÈGLE 7 : K8S-PRIV-001 est Tier 2 (packages/detection/tier_classifier.py), pas Tier 1.
can_handle() est vrai (la règle est dans le périmètre fonctionnel de l'agent) mais
remediate() refuse tant que le garde-fou ci-dessous (BaseRemediationAgent._twin_check,
DEC-006) échoue. Ce n'est PAS le jumeau numérique de Phase 3 (P3.8/P3.9, pas encore
construit) --- Lara a explicitement choisi ce "garde-fou minimal avant action" plutôt que
de reclassifier la règle en Tier 1 ou de la laisser bloquée jusqu'à Phase 3.

Choix de conception assumé (DEC-006) : on ne patche JAMAIS directement le Pod ciblé par le
finding. En Kubernetes, `spec.containers[*].securityContext` d'un Pod existant est un champ
immuable --- l'API-serveur refuse ce patch avec une erreur 422, même en dry-run (ce n'est pas
une limitation de cet agent, c'est le comportement réel de l'API). Le correctif réel et
idiomatique est de patcher le Deployment propriétaire : son `spec.template` EST mutable, et
le contrôleur de rollout recrée alors les pods avec le nouveau securityContext. Si le pod
ciblé n'a pas de Deployment propriétaire identifiable (pod nu) --- pas de stratégie
déterministe sûre, refus explicite, jamais de suppression/recréation devinée.

Le garde-fou est donc un DRY-RUN RÉEL (`dry_run=["All"]`) du patch sur le Deployment,
exécuté contre l'API Kubernetes réelle juste avant toute décision d'exécuter. S'il échoue
--- cluster injoignable (cf. DECISIONS.md DEC-005 : le kubeconfig `cuz-reader` renvoie 401
aujourd'hui, limitation connue non bloquante), pod/Deployment ambigu ou introuvable, patch
refusé par l'admission --- l'agent refuse, fail-safe, sans jamais supposer que ça aurait marché.
"""

import logging
from typing import Any

from packages.agents.base_agent import AuditSink, BaseRemediationAgent
from packages.agents.vault_jit_client import VaultJITClient
from packages.connectors.kubernetes.connector import _owner_deployment
from packages.detection.models import Finding

logger = logging.getLogger(__name__)


def _desecurify_patch(pod: Any) -> dict[str, Any]:
    """Patch stratégique retirant privileged / runAsRoot de chaque conteneur du template du
    Deployment --- même correctif que le remediation_hint de K8S-PRIV-001
    (packages/detection/rules/network.py)."""
    return {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": c.name,
                            "securityContext": {"privileged": False, "runAsNonRoot": True},
                        }
                        for c in (pod.spec.containers or [])
                    ]
                }
            }
        }
    }


class KubernetesAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-k8s"
    handled_rule_ids = {"K8S-PRIV-001"}

    def __init__(
        self,
        vault_client: VaultJITClient,
        audit_sink: AuditSink,
        kubeconfig_path: str | None = None,
        core_v1: Any | None = None,
        apps_v1: Any | None = None,
    ):
        super().__init__(vault_client, audit_sink)
        if core_v1 is not None and apps_v1 is not None:
            # Injectés (tests) : aucun appel réseau à la construction de l'agent.
            self._core_v1, self._apps_v1 = core_v1, apps_v1
        elif kubeconfig_path:
            from kubernetes import client, config

            config.load_kube_config(config_file=kubeconfig_path)  # type: ignore[no-untyped-call, unused-ignore]
            self._core_v1 = client.CoreV1Api()
            self._apps_v1 = client.AppsV1Api()
        else:
            # Pas de cluster configuré : le garde-fou échoue toujours (fail-safe), l'agent
            # reste donc bloqué sur K8S-PRIV-001 exactement comme avant DEC-006.
            self._core_v1 = self._apps_v1 = None

    def _find_pod(self, pod_name: str) -> Any | None:
        """Pod unique portant ce nom, tous namespaces --- None si introuvable, ambigu, ou si
        le cluster est injoignable : jamais de correction sur une cible incertaine."""
        if self._core_v1 is None:
            return None
        try:
            matches = [
                p
                for p in self._core_v1.list_pod_for_all_namespaces().items
                if p.metadata.name == pod_name
            ]
        except Exception as exc:  # cluster injoignable (ex. DEC-005 : 401 du kubeconfig)
            logger.warning("K8S-PRIV-001 : cluster Kubernetes injoignable (%s)", exc)
            return None
        return matches[0] if len(matches) == 1 else None

    def _resolve_target(self, finding: Finding) -> tuple[Any, str] | None:
        """(pod, nom du Deployment propriétaire) ou None si la cible n'est pas identifiable
        sans ambiguïté, ou si le pod est nu (aucune stratégie déterministe pour un pod nu)."""
        if len(finding.affected_node_names) != 1:
            return None
        pod = self._find_pod(finding.affected_node_names[0])
        if pod is None:
            return None
        deployment = _owner_deployment(pod)
        if deployment is None:
            return None
        return pod, deployment

    def _twin_check(self, finding: Finding) -> bool:
        target = self._resolve_target(finding)
        if target is None:
            return False
        pod, deployment = target
        try:
            self._apps_v1.patch_namespaced_deployment(
                name=deployment,
                namespace=pod.metadata.namespace,
                body=_desecurify_patch(pod),
                dry_run=["All"],
            )
            return True
        except Exception as exc:
            logger.warning(
                "garde-fou K8S-PRIV-001 refusé pour %s/%s : %s",
                pod.metadata.namespace,
                deployment,
                exc,
            )
            return False

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        # _twin_check() vient de réussir (en dry-run) juste avant, dans remediate().
        # On résout à nouveau la cible (pas le dry-run) : si elle a changé entre les deux
        # appels (cas de figure très improbable, pas de verrou distribué ici), on refuse
        # plutôt que d'agir sur une résolution potentiellement périmée --- fail-safe.
        target = self._resolve_target(finding)
        if target is None:
            raise RuntimeError(
                "K8S-PRIV-001 : la cible n'a pas pu être résolue à nouveau avant "
                "l'exécution réelle --- refus fail-safe (cf. DECISIONS.md DEC-006)"
            )
        pod, deployment = target
        self._apps_v1.patch_namespaced_deployment(
            name=deployment,
            namespace=pod.metadata.namespace,
            body=_desecurify_patch(pod),
        )
        return {
            "action": "deployment_security_context_patched",
            "target": finding.affected_nodes,
            "namespace": pod.metadata.namespace,
            "deployment": deployment,
        }
