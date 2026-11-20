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

DEC-006 (garde-fou minimal Tier 2) : can_automate_finding() reste le SEUL chemin
d'autorisation pour le Tier 1 (inchangé). Pour le Tier 2 (K8S-PRIV-001, IAC-DRIFT-001),
il n'existe toujours pas de jumeau numérique (Phase 3, P3.8/P3.9) --- mais un agent peut
désormais fournir un _twin_check() réel (pas une simulation) qui, pour CE finding précis,
vérifie contre le système cible réel qu'une action serait acceptée avant de l'exécuter
(cf. KubernetesAgent). Par défaut, _twin_check() renvoie False : un agent qui ne
l'implémente pas reste bloqué en Tier 2, comme avant. RÈGLE 3 (confiance, statut ouvert)
s'applique dans tous les cas, avant même d'envisager un garde-fou Tier 2.

DEC-007 (P2.12, audit_sink devenu async) : AuditSink.record() est désormais une coroutine,
AWAITÉE à chaque appel --- plus de fire-and-forget. L'ancien contrat synchrone (P2.11,
écrit avant que packages/audit/ existe) était un simple duck-type en attendant
l'implémentation réelle ; la implémenter en fire-and-forget (asyncio.create_task non
attendu) aurait permis de perdre silencieusement un événement d'audit (DB indisponible,
process tué juste après le retour de remediate()) --- exactement ce que RÈGLE 4 interdit
("pas de changement d'état sans trace", cf. services/api/audit.py). Voir DECISIONS.md
DEC-007 pour le détail de cet écart face au guide P2.12.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Any, Protocol

from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding
from packages.detection.tier_classifier import (
    MIN_CONFIDENCE_FOR_AUTOMATION,
    Tier,
    can_automate_finding,
    classify,
)


class AuditSink(Protocol):
    """Interface minimale attendue de l'audit sink (P2.12, packages/audit/audit_sink.py).
    Duck-typing volontaire : un agent ne dépend jamais d'une implémentation concrète,
    seulement de ce contrat. record() est une coroutine --- toujours awaitée par
    remediate(), jamais en fire-and-forget (DEC-007)."""

    async def record(
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

    def _twin_check(self, finding: Finding) -> bool:
        """Garde-fou minimal Tier 2 (DEC-006) --- PAS le jumeau numérique de Phase 3
        (P3.8/P3.9) : par défaut, aucun --- un agent reste bloqué sur un finding Tier 2
        tant qu'il ne fournit pas sa propre vérification réelle avant exécution
        (cf. KubernetesAgent._twin_check pour l'implémentation de référence)."""
        return False

    def _is_authorized(self, finding: Finding) -> bool:
        if can_automate_finding(finding):
            return True
        # RÈGLE 3 : même pour envisager un garde-fou Tier 2, le finding doit être ouvert
        # et suffisamment confiant --- ce n'est jamais le garde-fou seul qui autorise.
        if finding.status != "open" or finding.confidence_score < MIN_CONFIDENCE_FOR_AUTOMATION:
            return False
        if classify(finding.rule_id) != Tier.TIER_2:
            return False
        return self._twin_check(finding)

    async def remediate(self, finding: Finding) -> dict[str, Any]:
        if not self.can_handle(finding):
            raise ValueError(f"{self.__class__.__name__} ne gère pas {finding.rule_id}")

        if not self._is_authorized(finding):
            # RÈGLE 3 (confidence_score >= 0.7, status == "open") + RÈGLE 7 (Tier 1
            # autonome ; Tier 2 seulement si _twin_check() réussit) : un agent peut "gérer"
            # une règle dans son périmètre (can_handle) sans pour autant être autorisé à
            # agir sur CE finding précis. Fail-safe, comme can_automate_finding() partout
            # ailleurs dans le repo.
            raise PermissionError(
                f"{finding.rule_id} n'est pas automatisable pour ce finding "
                f"(tier={finding.tier}, confidence_score={finding.confidence_score}, "
                f"status={finding.status}) --- RÈGLE 3/7"
            )

        action_id = str(uuid.uuid4())
        credential = self.vault_client.acquire_jit_credential(self.vault_role)
        # finding_id passé explicitement (pas seulement dans payload) --- c'est une
        # colonne indexée dédiée de audit_events (idx_audit_events_finding), pas un champ
        # JSONB à parser pour retrouver "toutes les actions sur ce finding" (DEC-007).
        await self.audit_sink.record(
            "jit_credential_acquired",
            action_id,
            {
                "agent": self.__class__.__name__,
                "role": self.vault_role,
                "lease_id": credential["lease_id"],
            },
            finding_id=finding.id,
        )
        try:
            result = await self._execute(finding, credential)
            await self.audit_sink.record(
                "remediation_executed",
                action_id,
                {"agent": self.__class__.__name__, "result": result},
                finding_id=finding.id,
            )
            return result
        finally:
            # Révocation SYSTÉMATIQUE, même en cas d'exception --- RÈGLE 6.
            revoked = self.vault_client.revoke(credential["lease_id"])
            await self.audit_sink.record(
                "jit_credential_revoked",
                action_id,
                {"lease_id": credential["lease_id"], "revoked": revoked},
                finding_id=finding.id,
            )
