# packages/agents/iam_agent.py
"""Agent Tier 1 (RÈGLE 7) pour IAM-001 et CIS-011. Les deux sont Tier 1
(packages/detection/tier_classifier.py) mais n'ont pas le même sort aujourd'hui (DEC-006) :

- CIS-011 (rôle admin permanent) : correctif IaC déterministe vérifié
  (packages/remediation/terraform_edit.py:revoke_permanent_admin) --- commit direct (pas de
  PR) sur le dépôt Gitea via GitOpsPRGenerator.apply_direct(), réellement opérationnel.
- IAM-001 (identité sans MFA) : AUCUNE permission Graph en écriture n'existe aujourd'hui
  (packages/connectors/entra_id/connector.py est lecture seule, scope `.default` --- DEC-001).
  Lara a choisi d'ajouter une permission Graph en écriture côté Azure, mais a explicitement
  différé cette étape ("plus tard, avance sur le reste d'abord"). Tant que ce n'est pas fait,
  _execute() refuse explicitement --- JAMAIS de faux succès. C'est précisément l'écart que
  corrige DEC-006 par rapport au stub d'origine, qui prétendait "mfa_enforced_or_role_scoped"
  sans jamais appeler la moindre API.
"""

from typing import Any

from packages.agents.base_agent import AuditSink, BaseRemediationAgent
from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding
from packages.remediation.gitops_pr_generator import (
    GitOpsPRGenerator,
    RemediationNotApplicableError,
)


class IAMAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-iam"
    handled_rule_ids = {"IAM-001", "CIS-011"}

    def __init__(
        self,
        vault_client: VaultJITClient,
        audit_sink: AuditSink,
        gitops: GitOpsPRGenerator | None = None,
    ):
        super().__init__(vault_client, audit_sink)
        self._gitops = gitops

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        if finding.rule_id == "IAM-001":
            raise RemediationNotApplicableError(
                "IAM-001 : aucune permission Graph en écriture n'est configurée aujourd'hui "
                "(connecteur Entra ID en lecture seule) --- voir DECISIONS.md DEC-006 pour "
                "l'étape Azure (permission + consentement admin) à faire avant que cet agent "
                "devienne opérationnel sur cette règle. Décision explicite de Lara : différée."
            )
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
