# packages/detection/tests/test_tier_classifier.py
import re
from pathlib import Path

import pytest

from packages.detection.models import Finding
from packages.detection.mutation_router import registered_rules
from packages.detection.tier_classifier import (
    MIN_CONFIDENCE_FOR_AUTOMATION,
    RULE_TIER_MAPPING,
    Tier,
    can_automate,
    can_automate_finding,
    classify,
)

OPA_DIR = Path(__file__).resolve().parents[1] / "rules" / "opa"


def _opa_rule_ids() -> set[str]:
    return {
        rule_id
        for rego in OPA_DIR.glob("*.rego")
        for rule_id in re.findall(r'"rule_id":\s*"([^"]+)"', rego.read_text())
    }


def _finding(rule_id: str = "NET-001", confidence: float = 0.9, status: str = "open") -> Finding:
    return Finding(
        tenant_id="acmecorp",
        rule_id=rule_id,
        severity="HIGH",
        title="t",
        description="d",
        affected_nodes=["n1"],
        affected_node_names=["n1"],
        remediation_hint="h",
        confidence_score=confidence,
        status=status,  # type: ignore[arg-type]
    )


# ── classification ──────────────────────────────────────────────────────────


def test_net_001_is_tier_1_and_automatable():
    assert classify("NET-001") == Tier.TIER_1
    assert can_automate("NET-001") is True


def test_attack_path_is_tier_3_not_automatable():
    assert classify("ATTACK-PATH-001-PARTIAL") == Tier.TIER_3
    assert can_automate("ATTACK-PATH-001-PARTIAL") is False


def test_unknown_rule_defaults_to_tier_4_and_is_never_automated():
    """Fail-safe : une règle non mappée n'est JAMAIS automatisée par défaut."""
    assert classify("UNMAPPED-RULE-999") == Tier.TIER_4
    assert can_automate("UNMAPPED-RULE-999") is False
    assert can_automate_finding(_finding("UNMAPPED-RULE-999", confidence=1.0)) is False


def test_cis_004_stale_node_is_tier_0_alert_only():
    """Décision explicite : un nœud stale n'appelle aucune remédiation, seulement une alerte."""
    assert classify("CIS-004") == Tier.TIER_0
    assert can_automate("CIS-004") is False
    assert can_automate_finding(_finding("CIS-004", confidence=1.0)) is False


def test_tier_0_rules_are_exactly_the_alert_only_ones():
    tier_0 = {r for r, t in RULE_TIER_MAPPING.items() if t == Tier.TIER_0}
    assert tier_0 == {"IAM-OPA-001", "CIS-004"}


def test_matching_is_case_sensitive():
    """`IaC-DRIFT-001` (faute du guide V3) ne désigne pas la vraie règle `IAC-DRIFT-001`."""
    assert classify("IAC-DRIFT-001") == Tier.TIER_2
    assert classify("IaC-DRIFT-001") == Tier.TIER_4


# ── cohérence avec les règles réellement enregistrées ───────────────────────


def test_every_registered_cypher_rule_has_an_explicit_tier():
    missing = set(registered_rules()) - set(RULE_TIER_MAPPING)
    assert not missing, f"règles Cypher sans tier explicite : {sorted(missing)}"


def test_every_opa_rule_has_an_explicit_tier():
    opa = _opa_rule_ids()
    assert len(opa) == 5, "5 règles OPA attendues, dossier rules/opa modifié ?"
    assert not opa - set(RULE_TIER_MAPPING), sorted(opa - set(RULE_TIER_MAPPING))


def test_no_mapping_entry_targets_a_nonexistent_rule():
    """Une faute de frappe dans une clé ne doit pas passer pour un Tier 4 par défaut."""
    real = set(registered_rules()) | _opa_rule_ids()
    assert not set(RULE_TIER_MAPPING) - real, sorted(set(RULE_TIER_MAPPING) - real)


def test_there_are_26_classified_rules():
    # P2.10 bis (DEC-004) : +3 règles Cypher (IAM-STALE-ROLE-001, NET-SSH-OPEN-001, CERT-EXPIRED-001)
    # P2.13 (DEC-008) : +1 règle Cypher (DORA-CONCENTRATION-001)
    assert len(registered_rules()) == 25
    assert len(RULE_TIER_MAPPING) == 30  # 25 Cypher + 5 OPA


# ── RÈGLE 7 : seul le Tier 1 s'automatise ───────────────────────────────────


def test_only_tier_1_rules_are_automatable():
    for rule_id, tier in RULE_TIER_MAPPING.items():
        assert can_automate(rule_id) is (tier == Tier.TIER_1), rule_id


def test_the_set_of_automatable_rules_is_pinned():
    """Ajouter une règle au Tier 1 (donc l'autoriser à agir seule) doit modifier ce test.

    P2.10 bis (DEC-004) : +3 entrées. can_automate() les autorise (Tier 1), mais seule
    NET-SSH-OPEN-001 a un correctif IaC vérifié dans SUPPORTED_RULES (gitops_pr_generator.py) ;
    IAM-STALE-ROLE-001/CERT-EXPIRED-001 restent Tier 1 sans jamais générer de PR (voir le
    docstring de packages/detection/rules/iac_tier1_extra.py).
    """
    tier_1 = {r for r, t in RULE_TIER_MAPPING.items() if t == Tier.TIER_1}
    assert tier_1 == {
        "NET-001",
        "STORAGE-PUBLIC-001",
        "IAM-001",
        "CIS-003",
        "CIS-011",
        "IAM-STALE-ROLE-001",
        "NET-SSH-OPEN-001",
        "CERT-EXPIRED-001",
    }


def test_tier_4_rules_are_never_automatable_even_with_perfect_confidence():
    for rule_id, tier in RULE_TIER_MAPPING.items():
        if tier == Tier.TIER_4:
            assert can_automate_finding(_finding(rule_id, confidence=1.0)) is False, rule_id


# ── RÈGLE 3 : seuil de confiance, statut ────────────────────────────────────


def test_finding_below_confidence_threshold_is_not_automatable():
    assert can_automate_finding(_finding("NET-001", confidence=0.69)) is False
    assert can_automate_finding(_finding("NET-001", confidence=0.0)) is False


def test_finding_at_threshold_is_automatable():
    assert MIN_CONFIDENCE_FOR_AUTOMATION == 0.7
    assert can_automate_finding(_finding("NET-001", confidence=0.7)) is True


@pytest.mark.parametrize("status", ["acknowledged", "false_positive", "resolved"])
def test_non_open_finding_is_never_automatable(status):
    assert can_automate_finding(_finding("NET-001", confidence=0.95, status=status)) is False


# ── champ tier du modèle Finding ────────────────────────────────────────────


def test_finding_carries_its_tier():
    assert _finding("NET-001").tier == 1
    assert _finding("K8S-PRIV-001").tier == 2
    assert _finding("OAUTH-LATERAL-001").tier == 3
    assert _finding("SHADOW-IT-001").tier == 4
    assert _finding("IAM-OPA-001").tier == 0
    assert _finding("CLOUD-ALERT").tier == 4  # alerte cloud : rule_id externe, jamais mappé


def test_tier_is_serialized():
    assert '"tier":1' in _finding("NET-001").model_dump_json().replace(" ", "")
    assert _finding("NET-001").model_dump()["tier"] == 1


def test_tier_cannot_be_forged_by_an_incoming_message():
    """Le consumer/l'API relisent des Finding en JSON : un `tier` falsifié est ignoré."""
    payload = _finding("SHADOW-IT-001").model_dump_json().replace('"tier":4', '"tier":1')
    payload = payload.replace('"tier": 4', '"tier": 1')
    assert '"tier": 1' in payload or '"tier":1' in payload
    assert Finding.model_validate_json(payload).tier == 4
