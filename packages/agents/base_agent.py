# packages/agents/base_agent.py
"""RÈGLE 6 (droits minimaux, un agent = un périmètre) ET RÈGLE 7 (seul le Tier 1
s'exécute de façon autonome) : remediate() ne se contente pas de vérifier que l'agent
sait traiter la règle (can_handle), il vérifie aussi que CE finding précis est
effectivement autorisé à être automatisé --- exactement le même garde-fou que
GitOpsPRGenerator.generate_pr() (P2.10, packages/remediation/gitops_pr_generator.py),
via can_automate_finding() (RÈGLE 3 : confidence_score >= 0.7, finding ouvert, Tier 1).

Le guide P2.11 d'origine omettait ce deuxième contrôle --- can_handle() seul laissait
passer un finding Tier 2+ ou de confiance insuffisante dès lors que son rule_id figurait
dans handled_rule_ids. C'était un oubli, pas un choix : le pattern RÈGLE 3/7 est déjà la
référence du repo pour toute action automatique (cf. tier_classifier.py). Voir
DECISIONS.md, DEC-006 pour le détail de cet écart et de celui de vault_jit_client.py.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Any, Protocol

from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding
from packages.detection.tier_classifier import can_automate_finding


class AuditSink(Protocol):
    """Interface minimale attendue de l'audit sink (P2.12, packages/audit/audit_sink.py,
    pas encore implémenté au moment de P2.11). Duck-typing volontaire : un agent ne dépend
    jamais d'une implémentation concrète, seulement de ce contrat."""

    def record(
        self,
        event_type: str,
        action_id: str,
        payload: dict[str, Any],
        finding_id: str | None = None,
    ) -> None: ...


class BaseRemediationAgent(ABC):
    """RÈGLE 6 : chaque agent a un périmètre limité (role Vault dédié), des droits
    minimaux, un objectif unique (une seule famille de règles traitée par agent)."""

    vault_role: str
    handled_rule_ids: set[str]

    def __init__(self, vault_client: VaultJITClient, audit_sink: AuditSink):
        self.vault_client = vault_client
        self.audit_sink = audit_sink  # P2.12 : écrit en append-only

    def can_handle(self, finding: Finding) -> bool:
        return finding.rule_id in self.handled_rule_ids

    @abstractmethod
    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]: ...

    async def remediate(self, finding: Finding) -> dict[str, Any]:
        if not self.can_handle(finding):
            raise ValueError(f"{self.__class__.__name__} ne gère pas {finding.rule_id}")

        if not can_automate_finding(finding):
            # RÈGLE 3 (confidence_score >= 0.7, status == "open") + RÈGLE 7 (Tier 1
            # uniquement) : un agent peut "gérer" une règle dans son périmètre
            # (can_handle) sans pour autant être autorisé à agir sur CE finding précis.
            # Fail-safe, comme can_automate_finding() partout ailleurs dans le repo.
            raise PermissionError(
                f"{finding.rule_id} n'est pas automatisable pour ce finding "
                f"(tier={finding.tier}, confidence_score={finding.confidence_score}, "
                f"status={finding.status}) --- RÈGLE 3/7"
            )

        action_id = str(uuid.uuid4())
        credential = self.vault_client.acquire_jit_credential(self.vault_role)
        self.audit_sink.record(
            "jit_credential_acquired",
            action_id,
            {
                "agent": self.__class__.__name__,
                "role": self.vault_role,
                "lease_id": credential["lease_id"],
                "finding_id": finding.id,
            },
        )
        try:
            result = await self._execute(finding, credential)
            self.audit_sink.record(
                "remediation_executed",
                action_id,
                {"agent": self.__class__.__name__, "finding_id": finding.id, "result": result},
            )
            return result
        finally:
            # Révocation SYSTÉMATIQUE, même en cas d'exception --- RÈGLE 6.
            revoked = self.vault_client.revoke(credential["lease_id"])
            self.audit_sink.record(
                "jit_credential_revoked",
                action_id,
                {"lease_id": credential["lease_id"], "revoked": revoked},
            )
