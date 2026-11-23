# packages/detection/tier_classifier.py
"""Classification des findings par tiers de criticité opérationnelle (P2.9).

Mapping rule_id -> tier. Toute règle absente est traitée comme Tier 4 (RÈGLE 7 : jamais
d'automatisation par défaut sur un finding non classifié, fail-safe plutôt que fail-open).

La correspondance est EXACTE (sensible à la casse) : `IaC-DRIFT-001` ne désigne pas `IAC-DRIFT-001`.
Les tests vérifient que chaque règle enregistrée (Cypher et OPA) a une entrée explicite et qu'aucune
entrée ne vise une règle inexistante : une faute de frappe ne peut donc pas passer pour un Tier 4 par défaut.

Origine des tiers : voir docs/tier-mapping.md. Les règles que le guide V3 ne classe pas sont en Tier 4
explicite, en attente d'arbitrage ; aucune n'a reçu d'automatisation par inférence. Seule exception,
décidée explicitement : CIS-004 (Tier 0).
"""

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - évite l'import circulaire avec models.py
    from packages.detection.models import Finding

# RÈGLE 3 (CLAUDE.md) : aucune action automatique sur un nœud dont confidence_score < 0.7
MIN_CONFIDENCE_FOR_AUTOMATION = 0.7


class Tier(IntEnum):
    TIER_0 = 0  # tag/alerte seulement, aucun impact
    TIER_1 = 1  # PR GitOps, réversible
    TIER_2 = 2  # jumeau requis avant exécution
    TIER_3 = 3  # canary + validation humaine
    TIER_4 = 4  # humain uniquement, jamais automatisé


RULE_TIER_MAPPING: dict[str, Tier] = {
    # ── Tier 1 : réversibles, génèrent une PR GitOps (P2.10) ────────────────────────────
    "NET-001": Tier.TIER_1,  # port SSH exposé -> fermer le port dans le NSG Terraform
    "STORAGE-PUBLIC-001": Tier.TIER_1,  # bucket public -> retirer la policy publique
    "IAM-001": Tier.TIER_1,  # identité sans MFA -> PR forçant la policy MFA (si gérée en IaC)
    "CIS-003": Tier.TIER_1,  # service sans owner -> PR ajoutant le tag
    "CIS-011": Tier.TIER_1,  # rôle admin permanent -> PR réduisant la portée du rôle
    # ── P2.10 bis (DEC-004) : 3 types Tier 1 supplémentaires, fixtures AcmeCorp fictives ─
    # Tier 1 car réversibles par nature (révoquer/fermer/renouveler), MAIS IAM-STALE-ROLE-001
    # et CERT-EXPIRED-001 n'ont pas de correctif IaC déterministe sûr : can_automate() les
    # autorise, SUPPORTED_RULES (gitops_pr_generator.py) les refuse quand même, explicitement.
    "IAM-STALE-ROLE-001": Tier.TIER_1,  # rôle inutilisé >90j -> à désactiver (pas de PR auto)
    "NET-SSH-OPEN-001": Tier.TIER_1,  # port 22 ouvert à 0.0.0.0/0 -> PR fermant le CIDR
    "CERT-EXPIRED-001": Tier.TIER_1,  # certificat expiré -> renouvellement (pas de PR auto)
    # ── Tier 2 : un jumeau avant exécution (Phase 3, P3.8/P3.9) ─────────────────────────
    "K8S-PRIV-001": Tier.TIER_2,  # pod privileged -> SecurityContext à tester
    "IAC-DRIFT-001": Tier.TIER_2,  # resynchronisation IaC, impact difficile à prévoir à l'aveugle
    # ── Tier 3 : canary + validation humaine (Phase 4) ──────────────────────────────────
    "ATTACK-PATH-001-PARTIAL": Tier.TIER_3,
    "OAUTH-LATERAL-001": Tier.TIER_3,
    # ── Tier 4 : humain uniquement ──────────────────────────────────────────────────────
    "DORA-THIRD-PARTY-001": Tier.TIER_4,  # décision contractuelle, pas technique
    "DORA-CONCENTRATION-001": Tier.TIER_4,  # diversification/plan de continuité, pas technique
    "SHADOW-IT-001": Tier.TIER_4,  # arbitrage métier (déclarer ou isoler l'actif)
    # ── Tier 0 : information seule ──────────────────────────────────────────────────────
    "IAM-OPA-001": Tier.TIER_0,
    # CIS-004 (nœud stale) : décision explicite, hors guide. Un nœud dont la fraîcheur est tombée sous 0.2
    # n'appelle aucune remédiation, seulement une alerte immédiate : c'est la définition du Tier 0.
    "CIS-004": Tier.TIER_0,
    # ── Non classées par le guide V3 : Tier 4 explicite, en attente d'arbitrage ─────────
    "CIS-001": Tier.TIER_4,
    "CIS-002": Tier.TIER_4,
    "CIS-005": Tier.TIER_4,
    "CIS-006": Tier.TIER_4,
    "CIS-007": Tier.TIER_4,
    "CIS-008": Tier.TIER_4,
    "CIS-009": Tier.TIER_4,
    "CIS-010": Tier.TIER_4,
    "CIS-012": Tier.TIER_4,
    "NET-OPA-001": Tier.TIER_4,
    "TLS-OPA-001": Tier.TIER_4,
    "OWN-OPA-001": Tier.TIER_4,
    "STORAGE-OPA-001": Tier.TIER_4,
}


def classify(rule_id: str) -> Tier:
    return RULE_TIER_MAPPING.get(rule_id, Tier.TIER_4)


def can_automate(rule_id: str) -> bool:
    """RÈGLE 7 : seul le Tier 1 s'exécute de façon autonome, sans jumeau ni validation humaine.

    Ne regarde que la règle. Pour décider d'agir sur un finding précis, utiliser
    `can_automate_finding`, qui applique aussi la RÈGLE 3 (seuil de confiance).
    """
    return classify(rule_id) == Tier.TIER_1


def can_automate_finding(finding: "Finding") -> bool:
    """Un finding ne déclenche une action automatique que s'il cumule : règle Tier 1, finding ouvert,
    confidence_score >= 0.7 (RÈGLE 3). Un finding acquitté, faux positif ou résolu n'agit jamais."""
    return (
        can_automate(finding.rule_id)
        and finding.status == "open"
        and finding.confidence_score >= MIN_CONFIDENCE_FOR_AUTOMATION
    )
