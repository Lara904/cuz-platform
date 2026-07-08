# tests/unit/test_scoring.py
"""
P0.6 — Tests des scores de confiance et de fraîcheur.

Couverture des 20 cas requis :
  - Confiance : mono-source, 2 sources, 3 sources, scores à la limite, source inconnue, liste vide
  - Fraîcheur : 7 types de nœuds différents, décroissance à 0 j / 7 j / 30 j
"""

import math
import pytest
from datetime import datetime, timedelta, timezone

from packages.core.models.enums import NodeType
from packages.core.scoring.confidence import compute_confidence, DEFAULT_SOURCE_WEIGHTS
from packages.core.scoring.freshness import compute_freshness, HALF_LIFE_DAYS, DEFAULT_HALF_LIFE


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _last_seen(days_ago: float) -> datetime:
    """Retourne un datetime utcnow - days_ago jours, sans timezone (cohérent avec compute_freshness)."""
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def _expected_freshness(node_type: NodeType, days_ago: float) -> float:
    """Calcule la valeur théorique attendue pour faciliter les assertions."""
    half_life = HALF_LIFE_DAYS.get(node_type, DEFAULT_HALF_LIFE)
    lam = math.log(2) / half_life
    return round(math.exp(-lam * days_ago), 4)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 1 — Score de confiance (compute_confidence)
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeConfidence:

    # ── Cas 1 : liste vide → 0.0 (item P0.6 checklist) ──────────────────────
    def test_empty_sources_returns_zero(self):
        """Aucune source → confiance nulle."""
        assert compute_confidence([]) == 0.0

    # ── Cas 2 : mono-source azure (poids 0.95) ───────────────────────────────
    def test_mono_source_azure(self):
        """1 source connue → confidence == poids de la source."""
        assert compute_confidence(['azure']) == 0.95

    # ── Cas 3 : mono-source servicenow (poids 0.80) ──────────────────────────
    def test_mono_source_servicenow(self):
        """ServiceNow seul = 0.80 (CMDB manuel, poids plus faible)."""
        assert compute_confidence(['servicenow']) == 0.80

    # ── Cas 4 : mono-source source inconnue → fallback 0.5 ───────────────────
    def test_mono_source_unknown_falls_back_to_half(self):
        """Source non référencée → poids par défaut 0.5."""
        score = compute_confidence(['datadog_unknown'])
        assert score == pytest.approx(0.5, abs=1e-4)

    # ── Cas 5 : 2 sources indépendantes (azure + entra_id) ───────────────────
    def test_two_sources_azure_and_entra_id(self):
        """
        azure=0.95, entra_id=0.95
        confidence = 1 - (0.05 × 0.05) = 0.9975
        """
        score = compute_confidence(['azure', 'entra_id'])
        assert score == pytest.approx(0.9975, abs=1e-4)

    # ── Cas 6 : 2 sources, poids asymétriques (azure + servicenow) ───────────
    def test_two_sources_azure_and_servicenow(self):
        """
        azure=0.95, servicenow=0.80
        confidence = 1 - (0.05 × 0.20) = 0.99
        """
        score = compute_confidence(['azure', 'servicenow'])
        assert score == pytest.approx(0.99, abs=1e-4)

    # ── Cas 7 : 2 sources, github + sentinel ─────────────────────────────────
    def test_two_sources_github_and_sentinel(self):
        """
        github=0.90, sentinel=0.85
        confidence = 1 - (0.10 × 0.15) = 0.985
        """
        expected = round(1 - (0.10 * 0.15), 4)
        score = compute_confidence(['github', 'sentinel'])
        assert score == pytest.approx(expected, abs=1e-4)

    # ── Cas 8 : 3 sources (github + azure + servicenow) ──────────────────────
    def test_three_sources_github_azure_servicenow(self):
        """
        github=0.90, azure=0.95, servicenow=0.80
        confidence = 1 - (0.10 × 0.05 × 0.20) = 0.999
        """
        expected = round(1 - (0.10 * 0.05 * 0.20), 4)
        score = compute_confidence(['github', 'azure', 'servicenow'])
        assert score == pytest.approx(expected, abs=1e-4)

    # ── Cas 9 : 3 sources dont une inconnue ──────────────────────────────────
    def test_three_sources_with_unknown(self):
        """
        azure=0.95, kubernetes=0.92, source_inconnue=0.5 (fallback)
        confidence = 1 - (0.05 × 0.08 × 0.50) = 0.998
        """
        expected = round(1 - (0.05 * 0.08 * 0.50), 4)
        score = compute_confidence(['azure', 'kubernetes', 'mystery_source'])
        assert score == pytest.approx(expected, abs=1e-4)

    # ── Cas 10 : score à la limite basse (poids unique très faible) ──────────
    def test_limit_low_single_source_custom_weight(self):
        """Source avec poids minimal = 0.01 → confidence voisine de 0.01."""
        custom_weights = {'weak_source': 0.01}
        score = compute_confidence(['weak_source'], weights=custom_weights)
        assert score == pytest.approx(0.01, abs=1e-4)

    # ── Cas 11 : score à la limite haute (poids unique = 1.0) ────────────────
    def test_limit_high_single_source_perfect_weight(self):
        """Source avec poids = 1.0 → confidence = 1.0 (certitude absolue)."""
        custom_weights = {'perfect_source': 1.0}
        score = compute_confidence(['perfect_source'], weights=custom_weights)
        assert score == pytest.approx(1.0, abs=1e-4)

    # ── Cas 12 : ordre des sources n'affecte pas le résultat ─────────────────
    def test_source_order_is_commutative(self):
        """La formule bayésienne est commutative : l'ordre des sources importe peu."""
        s1 = compute_confidence(['azure', 'servicenow', 'github'])
        s2 = compute_confidence(['github', 'azure', 'servicenow'])
        assert s1 == s2

    # ── Cas 13 : weights personnalisés par tenant ─────────────────────────────
    def test_custom_tenant_weights_override_defaults(self):
        """Un tenant peut redéfinir les poids — vérifier que le custom l'emporte."""
        tenant_weights = {'servicenow': 0.60}   # Ce tenant fait moins confiance au CMDB
        score = compute_confidence(['servicenow'], weights=tenant_weights)
        assert score == pytest.approx(0.60, abs=1e-4)
        # Le poids par défaut (0.80) ne doit PAS être utilisé
        assert score != pytest.approx(0.80, abs=1e-4)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 2 — Score de fraîcheur (compute_freshness)
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeFreshness:

    # ── Cas 14 : t = 0 → score ≈ 1.0 (quel que soit le type) ────────────────
    def test_freshness_at_t0_is_one(self):
        """Un nœud vu à l'instant T est à fraîcheur maximale, quel que soit son type."""
        for node_type in [
            NodeType.VIRTUAL_MACHINE,
            NodeType.USER,
            NodeType.VULNERABILITY,
        ]:
            score = compute_freshness(node_type, _last_seen(0))
            assert score == pytest.approx(1.0, abs=0.005), \
                f"{node_type.value} à t=0 devrait être ~1.0, got {score}"

    # ── Cas 15 : VM / Serveur — demi-vie 7 jours → freshness(7j) ≈ 0.50 ─────
    def test_virtual_machine_decay_at_7_days(self):
        """VM : half-life = 7 j → à 7 jours exactement, score = 0.50 (± 0.01)."""
        score = compute_freshness(NodeType.VIRTUAL_MACHINE, _last_seen(7))
        assert score == pytest.approx(0.50, abs=0.01)

    # ── Cas 16 : VM / Serveur — freshness(30j) fortement dégradée ────────────
    def test_virtual_machine_decay_at_30_days(self):
        """VM à 30 j : très dégradé, le guide indique ~0.06."""
        score = compute_freshness(NodeType.VIRTUAL_MACHINE, _last_seen(30))
        assert score == pytest.approx(0.051, abs=0.01)   # valeur exacte : exp(-ln2/7*30) ≈ 0.0513

    # ── Cas 17 : Utilisateur IAM — demi-vie 1 jour → chute rapide ────────────
    def test_user_iam_decay_at_7_days(self):
        """
        Utilisateur IAM : half-life = 1 j → chute très rapide.

        Note : à 2 jours exactement, f(2) = (½)² = 0.25 (valeur mathématique exacte).
        La checklist P0.6 indique '< 0.25' — le test utilise '<= 0.25' pour rester
        conforme à l'intention (valeur déjà très dégradée) sans rejeter la valeur exacte.
        À 7 jours le score est < 0.01, ce qui est l'assertion forte.
        """
        score = compute_freshness(NodeType.USER, _last_seen(7))
        score_2j = compute_freshness(NodeType.USER, _last_seen(2))
        # À 2 jours : 0.25 (mi-vie au carré) — déjà très dégradé
        assert score_2j <= 0.25
        # À 7 jours : (½)^7 ≈ 0.0078 — quasi zéro
        assert score < 0.02

    # ── Cas 18 : Application — demi-vie 30 jours → lente décroissance ────────
    def test_application_decay_at_7_days(self):
        """Application : half-life = 30 j → à 7 jours, score encore élevé (~0.85)."""
        score = compute_freshness(NodeType.APPLICATION, _last_seen(7))
        assert score == pytest.approx(0.85, abs=0.02)

    def test_application_decay_at_30_days(self):
        """Application à 30 j = 0.50 (mi-vie atteinte)."""
        score = compute_freshness(NodeType.APPLICATION, _last_seen(30))
        assert score == pytest.approx(0.50, abs=0.01)

    # ── Cas 19 : Repository Git — demi-vie 14 jours ───────────────────────────
    def test_repository_decay_at_7_days(self):
        """Repository : half-life = 14 j → à 7 jours, score ≈ 0.71 (√½)."""
        score = compute_freshness(NodeType.REPOSITORY, _last_seen(7))
        assert score == pytest.approx(0.7071, abs=0.02)

    def test_repository_decay_at_30_days(self):
        """Repository à 30 j ≈ 0.23 (guide indique 0.22)."""
        score = compute_freshness(NodeType.REPOSITORY, _last_seen(30))
        assert score == pytest.approx(0.226, abs=0.02)

    # ── Cas 20a : Vulnerability (CVE) — demi-vie 3 jours, très volatile ──────
    def test_vulnerability_decay_at_7_days(self):
        """CVE : half-life = 3 j → à 7 jours, très faible (~0.20)."""
        score = compute_freshness(NodeType.VULNERABILITY, _last_seen(7))
        assert score == pytest.approx(0.198, abs=0.02)

    # ── Cas 20b : Prestataire tiers — demi-vie 90 jours, très stable ─────────
    def test_third_party_decay_at_7_days(self):
        """Tiers : half-life = 90 j → à 7 jours, encore très frais (~0.95)."""
        score = compute_freshness(NodeType.THIRD_PARTY, _last_seen(7))
        assert score == pytest.approx(0.9475, abs=0.02)

    def test_third_party_decay_at_30_days(self):
        """Tiers à 30 j ≈ 0.79 (guide indique 0.79)."""
        score = compute_freshness(NodeType.THIRD_PARTY, _last_seen(30))
        assert score == pytest.approx(0.7937, abs=0.02)

    # ── Cas bonus : NETWORK — partage la demi-vie 7j avec les VM ─────────────
    def test_network_same_half_life_as_vm(self):
        """Règle réseau (NSG) : half-life = 7 j, même comportement que VM."""
        vm_score = compute_freshness(NodeType.VIRTUAL_MACHINE, _last_seen(7))
        net_score = compute_freshness(NodeType.NETWORK, _last_seen(7))
        assert vm_score == net_score  # demi-vies identiques → scores identiques

    # ── Cas bonus : DATABASE — demi-vie 14 jours (même que REPOSITORY) ───────
    def test_database_decay_at_0_days(self):
        """Database à t=0 → 1.0."""
        score = compute_freshness(NodeType.DATABASE, _last_seen(0))
        assert score == pytest.approx(1.0, abs=0.005)

    # ── Cas bonus : type inconnu → DEFAULT_HALF_LIFE = 14 jours ──────────────
    def test_default_half_life_used_for_unknown_type(self):
        """
        Les types sans entrée dans HALF_LIFE_DAYS utilisent DEFAULT_HALF_LIFE = 14 j.
        CONTAINER n'est pas dans le dict → demi-vie de 14 jours.
        À 14 jours le score doit être ≈ 0.50.
        """
        assert NodeType.CONTAINER not in HALF_LIFE_DAYS, \
            "CONTAINER ne doit pas être dans HALF_LIFE_DAYS pour que ce test soit pertinent"
        score = compute_freshness(NodeType.CONTAINER, _last_seen(14))
        assert score == pytest.approx(0.50, abs=0.01)

    # ── Intégration confiance × fraîcheur : vérifier les seuils métier ───────
    def test_confidence_threshold_for_auto_action(self):
        """
        Règle métier : aucune action auto si confidence_score < 0.7.
        Une source avec poids 0.6 doit passer en dessous du seuil.
        """
        custom = {'weak_cmdb': 0.60}
        score = compute_confidence(['weak_cmdb'], weights=custom)
        assert score < 0.7, "Ce nœud doit bloquer l'action automatique"

    def test_two_sources_push_above_threshold(self):
        """
        Même source faible (0.60) + azure (0.95) → confiance > 0.7.
        Le croisement de sources permet de débloquer l'action auto.
        """
        custom = {'weak_cmdb': 0.60, 'azure': 0.95}
        score = compute_confidence(['weak_cmdb', 'azure'], weights=custom)
        assert score >= 0.7