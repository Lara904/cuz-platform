# packages/detection/rules/dora.py
from packages.detection.rules import RuleSpec, make_rule

# Débloquée par FIX-1 : sans THIRD_PARTY créés depuis ServiceNow, elle ne matchait jamais.
DORA_THIRD_PARTY_001 = RuleSpec(
    rule_id="DORA-THIRD-PARTY-001",
    severity="HIGH",
    title="Prestataire TIC critique sans plan de sortie",
    description="Un prestataire tiers supporte un service sans plan de sortie documenté.",
    remediation_hint="Documenter un plan de sortie (exit plan) pour ce prestataire.",
    cypher="""
MATCH (tp:CuzNode {tenant_id: $tenant_id, node_type: 'THIRD_PARTY'})
      -[:CUZ_EDGE {edge_type: 'SUPPORTS'}]->(bf:CuzNode)
WHERE tp.exit_plan_status IS NULL
RETURN [tp.id] AS node_ids, [tp.name] AS node_names
""",
)

RULES = [make_rule(DORA_THIRD_PARTY_001)]
