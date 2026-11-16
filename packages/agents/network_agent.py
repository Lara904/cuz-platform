# packages/agents/network_agent.py
"""Agent Tier 1 (RÈGLE 7) pour les deux règles réseau/stockage à correctif déterministe
vérifié (packages/remediation/terraform_edit.py) : STORAGE-PUBLIC-001 et NET-SSH-OPEN-001.

Écart par rapport au guide P2.11 d'origine, corrigé ici (DEC-006) : le guide référençait
NET-001, mais le Cypher de NET-001 (packages/detection/rules/network.py) filtre
`node_type IN ['SERVER', 'CONTAINER', 'CLUSTER']`, alors que la seule ressource réelle
AcmeCorp exposant SSH (`aws_security_group_rule`, cf. packages/connectors/terraform/
mapper.py) est mappée en NodeType.NETWORK --- NET-001 ne peut donc JAMAIS matcher un actif
réel. NET-SSH-OPEN-001 est la règle Tier 1 équivalente qui matche réellement (même
convention déjà utilisée par GitOpsPRGenerator.SUPPORTED_RULES, P2.10 bis / DEC-004).

Deux actions réelles, deux mécanismes différents :
- STORAGE-PUBLIC-001 : appel direct à l'API MinIO réelle (retrait de la policy publique du
  bucket) --- pas de Terraform ici, le connecteur MinIO (packages/connectors/minio_connector/
  connector.py) confirme que ce repo appelle déjà l'API MinIO de façon synchrone depuis du
  code async, sans executor ; on suit le même pattern.
- NET-SSH-OPEN-001 : commit direct (pas de PR) sur le dépôt IaC Gitea, via
  GitOpsPRGenerator.apply_direct() (même planification/garde-fous que les PR P2.10, sans
  branche ni revue humaine en attente --- justifié ici par le fait qu'un agent JIT n'a de
  toute façon accès qu'à une fenêtre de quelques minutes, RÈGLE 6).
"""

from typing import Any

from packages.agents.base_agent import AuditSink, BaseRemediationAgent
from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding
from packages.remediation.gitops_pr_generator import GitOpsPRGenerator


class NetworkAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-network"
    handled_rule_ids = {"NET-SSH-OPEN-001", "STORAGE-PUBLIC-001"}

    def __init__(
        self,
        vault_client: VaultJITClient,
        audit_sink: AuditSink,
        gitops: GitOpsPRGenerator | None = None,
        minio_client: Any | None = None,
    ):
        super().__init__(vault_client, audit_sink)
        # Injectés (jamais construits ici) : un agent ne décide pas comment on se connecte
        # à Gitea/MinIO, il consomme un client déjà configuré --- testable sans réseau réel.
        self._gitops = gitops
        self._minio = minio_client

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        if finding.rule_id == "STORAGE-PUBLIC-001":
            return await self._privatize_bucket(finding)
        return await self._close_ssh(finding)

    async def _privatize_bucket(self, finding: Finding) -> dict[str, Any]:
        if self._minio is None:
            raise RuntimeError(
                "NetworkAgent sans client MinIO configuré --- impossible de corriger "
                "STORAGE-PUBLIC-001 réellement (cf. DECISIONS.md DEC-006)"
            )
        if len(finding.affected_node_names) != 1:
            raise RuntimeError("STORAGE-PUBLIC-001 : un seul bucket attendu par finding")
        bucket = finding.affected_node_names[0]
        # Un bucket MinIO sans policy explicite est privé par défaut --- même sémantique que
        # make_bucket_private() côté Terraform (P2.10) : retirer la policy = le rendre privé.
        self._minio.delete_bucket_policy(bucket)
        return {
            "action": "bucket_privatized",
            "target": finding.affected_nodes,
            "bucket": bucket,
        }

    async def _close_ssh(self, finding: Finding) -> dict[str, Any]:
        if self._gitops is None:
            raise RuntimeError(
                "NetworkAgent sans GitOpsPRGenerator configuré --- impossible de corriger "
                "NET-SSH-OPEN-001 réellement (cf. DECISIONS.md DEC-006)"
            )
        result = await self._gitops.apply_direct(finding, actor="agent-network")
        return {
            "action": "security_group_rule_closed",
            "target": finding.affected_nodes,
            "file_path": result.file_path,
            "commit_sha": result.commit_sha,
        }
