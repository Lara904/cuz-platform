# packages/detection/tests/test_dora.py
"""Règles DORA (packages/detection/rules/dora.py) : DORA-THIRD-PARTY-001 (pré-existante, non
testée jusqu'ici) et DORA-CONCENTRATION-001 (P2.13, DEC-008). Même style que
test_iac_tier1_extra.py : session Neo4j simulée, aucune base réelle."""

from unittest.mock import MagicMock

from packages.detection.models import Finding
from packages.detection.rules import dora, make_rule
from packages.detection.rules.dora import DORA_CONCENTRATION_001, DORA_THIRD_PARTY_001

TENANT = "acmecorp"


def _session(rows: list[dict]) -> MagicMock:
    session = MagicMock()
    session.run.return_value.data.return_value = rows
    return session


def test_rule_count_matches_defined_rules():
    assert {r.spec.rule_id for r in dora.RULES} == {
        "DORA-THIRD-PARTY-001",
        "DORA-CONCENTRATION-001",
    }


def test_every_cypher_filters_on_tenant_and_returns_node_lists():
    for rule in dora.RULES:
        cypher = rule.spec.cypher
        assert "$tenant_id" in cypher, rule.spec.rule_id
        assert "node_ids" in cypher and "node_names" in cypher, rule.spec.rule_id


def test_no_contains_on_json_attributes():
    """FIX-3 : filtre sur des propriétés natives, jamais un CONTAINS sur le blob JSON."""
    for rule in dora.RULES:
        assert "CONTAINS" not in rule.spec.cypher, rule.spec.rule_id


# ── DORA-THIRD-PARTY-001 (pré-existante) ────────────────────────────────────


def test_third_party_without_exit_plan_builds_a_finding():
    session = _session([{"node_ids": ["tp-1"], "node_names": ["Acme-Payment-SaaS"]}])
    findings = make_rule(DORA_THIRD_PARTY_001)(session, TENANT)
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.rule_id == "DORA-THIRD-PARTY-001"
    assert finding.tier == 4


def test_third_party_empty_result_produces_no_finding():
    assert make_rule(DORA_THIRD_PARTY_001)(_session([]), TENANT) == []


# ── DORA-CONCENTRATION-001 (P2.13) ──────────────────────────────────────────


def test_concentration_rule_returns_finding_above_3_functions():
    session = _session(
        [
            {
                "node_ids": ["tp1"],
                "node_names": ["Acme-Payment-SaaS"],
                "critical_functions_count": 3,
                "function_names": ["Paiement client", "Facturation", "Onboarding fournisseur"],
            }
        ]
    )
    findings = make_rule(DORA_CONCENTRATION_001)(session, TENANT)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DORA-CONCENTRATION-001"
    assert finding.severity == "HIGH"
    assert finding.tier == 4  # décision de diversification, jamais automatisée (RÈGLE 7)
    assert finding.affected_node_names == ["Acme-Payment-SaaS"]


def test_concentration_rule_keeps_count_and_function_names_in_metadata():
    """Les colonnes au-delà de node_ids/node_names sont conservées par make_rule dans
    Finding.metadata (packages/detection/rules/__init__.py) --- jamais perdues ni devinées."""
    session = _session(
        [
            {
                "node_ids": ["tp1"],
                "node_names": ["Acme-Payment-SaaS"],
                "critical_functions_count": 4,
                "function_names": ["A", "B", "C", "D"],
            }
        ]
    )
    finding = make_rule(DORA_CONCENTRATION_001)(session, TENANT)[0]
    assert finding.metadata["critical_functions_count"] == 4
    assert finding.metadata["function_names"] == ["A", "B", "C", "D"]


def test_concentration_rule_empty_result_produces_no_finding():
    """Le WHERE critical_functions_count >= 3 est porté par le Cypher (vérifié ici au niveau
    de son contrat : un Cypher ne renvoyant aucune ligne ne produit aucun Finding)."""
    assert make_rule(DORA_CONCENTRATION_001)(_session([]), TENANT) == []


def test_concentration_cypher_filters_on_business_function_or_process_and_criticality():
    cypher = DORA_CONCENTRATION_001.cypher
    assert "BUSINESS_FUNCTION" in cypher
    assert "BUSINESS_PROCESS" in cypher
    assert "criticality_raw" in cypher
    assert ">= 3" in cypher
