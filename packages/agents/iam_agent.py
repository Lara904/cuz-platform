# packages/agents/iam_agent.py
"""Agent Tier 1 (RÈGLE 7) pour IAM-001 et CIS-011. Les deux sont Tier 1
(packages/detection/tier_classifier.py) mais n'ont pas le même mécanisme (DEC-006) :

- CIS-011 (rôle admin permanent) : correctif IaC déterministe vérifié
  (packages/remediation/terraform_edit.py:revoke_permanent_admin) --- commit direct (pas de
  PR) sur le dépôt Gitea via GitOpsPRGenerator.apply_direct().
- IAM-001 (identité sans MFA) : création d'une policy Conditional Access DÉDIÉE, scopée à
  l'utilisateur précis du finding, via GraphConditionalAccessClient
  (packages/agents/graph_ca_client.py). Nécessite la permission Graph
  `Policy.ReadWrite.ConditionalAccess` (ajoutée côté Azure --- cf. DEC-006) en plus de
  `Directory.Read.All` (déjà présente, DEC-001) utilisée pour résoudre l'utilisateur.

Garde-fous spécifiques à IAM-001, au-delà de RÈGLE 3/7 (touche l'authentification du
tenant, catégorie de risque différente d'un bucket ou d'une règle réseau) :
- `protected_display_names` : liste noire codée par le déployeur (jamais vide par défaut
  en prod) de comptes qu'on ne cible JAMAIS, quoi que dise le finding (admin, break-glass).
  C'est une défense en profondeur statique, pas une détection --- on ne devine jamais si un
  compte est "probablement" un admin, on refuse les noms explicitement listés.
- Résolution de l'utilisateur AVANT écriture (ambiguïté -> refus) et relecture APRÈS
  écriture (scope divergent -> refus), cf. GraphConditionalAccessClient.
"""

from typing import Any

from packages.agents.base_agent import AuditSink, BaseRemediationAgent
from packages.agents.graph_ca_client import GraphConditionalAccessClient
from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding
from packages.remediation.gitops_pr_generator import GitOpsPRGenerator


class IAMAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-iam"
    handled_rule_ids = {"IAM-001", "CIS-011"}

    def __init__(
        self,
        vault_client: VaultJITClient,
        audit_sink: AuditSink,
        gitops: GitOpsPRGenerator | None = None,
        graph_client: GraphConditionalAccessClient | Any | None = None,
        protected_display_names: frozenset[str] = frozenset(),
    ):
        super().__init__(vault_client, audit_sink)
        self._gitops = gitops
        self._graph_client = graph_client
        self._protected_display_names = protected_display_names

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        if finding.rule_id == "IAM-001":
            return await self._enforce_mfa(finding)
        if self._gitops is None:
            raise RuntimeError(
                "IAMAgent sans GitOpsPRGenerator configuré --- impossible de corriger "
                "CIS-011 réellement (cf. DECISIONS.md DEC-006)"
            )
        result = await self._gitops.apply_direct(finding, actor="agent-iam")
        return {
            "action": "permanent_admin_role_revoked",
            "target": finding.affected_nodes,
            "file_path": result.file_path,
            "commit_sha": result.commit_sha,
        }

    async def _enforce_mfa(self, finding: Finding) -> dict[str, Any]:
        if self._graph_client is None:
            raise RuntimeError(
                "IAMAgent sans client Graph configuré (Policy.ReadWrite.ConditionalAccess) "
                "--- impossible de corriger IAM-001 réellement (cf. DECISIONS.md DEC-006)"
            )
        if len(finding.affected_node_names) != 1:
            raise RuntimeError("IAM-001 : un seul utilisateur attendu par finding")

        display_name = finding.affected_node_names[0]
        if display_name in self._protected_display_names:
            raise PermissionError(
                f"IAM-001 : {display_name!r} figure dans la liste de comptes protégés "
                "(admin/break-glass) --- refus fail-safe, jamais d'action sur ces identités, "
                "quoi que dise le finding (cf. DECISIONS.md DEC-006)"
            )

        user_id = await self._graph_client.find_user_id_by_display_name(display_name)
        if user_id is None:
            raise RuntimeError(
                f"IAM-001 : utilisateur {display_name!r} introuvable ou ambigu dans Entra ID "
                "--- refus fail-safe, jamais d'action sur une cible incertaine"
            )

        policy = await self._graph_client.create_mfa_policy_for_user(user_id)
        return {
            "action": "conditional_access_mfa_policy_created",
            "target": finding.affected_nodes,
            "policy_id": policy["id"],
            "policy_display_name": policy["displayName"],
        }
