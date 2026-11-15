# packages/agents/kubernetes_agent.py
"""⚠️ Écart assumé (DECISIONS.md, DEC-006) : K8S-PRIV-001 est classé Tier 2 dans
tier_classifier.py (RULE_TIER_MAPPING) --- il nécessite un jumeau de validation avant
exécution (Phase 3, P3.8/P3.9), qui n'existe pas encore. Cet agent est donc code-complet
et testé, mais NON opérationnel sur sa cible prévue : can_handle() reste vrai (il sait
router la règle), mais remediate() refusera systématiquement ce finding tant que
K8S-PRIV-001 reste Tier 2 (RÈGLE 7, cf. base_agent.py). handled_rule_ids est laissé
identique au guide P2.11 pour documenter la cible visée, pas pour prétendre qu'elle est
active aujourd'hui.
"""

from typing import Any

from packages.agents.base_agent import BaseRemediationAgent
from packages.detection.models import Finding


class KubernetesAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-k8s"
    handled_rule_ids = {"K8S-PRIV-001"}

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        return {"action": "pod_security_context_patched", "target": finding.affected_nodes}
