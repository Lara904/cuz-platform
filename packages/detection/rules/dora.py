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

# P2.13 (DEC-008) : risque de concentration ICT (DORA Art. 29) --- un même prestataire
# (THIRD_PARTY) supporte 3+ fonctions/processus métier critiques via SUPPORTS (BUSINESS_FUNCTION
# ou BUSINESS_PROCESS, posés manuellement en P1.16 via business_process_loader.py en l'absence de
# ServiceNow ; le mapping cmdb_rel_ci -> SUPPORTS reste à écrire, cf. DEC-008).
#
# criticality_raw doit être une propriété Neo4j native pour être filtrable ici : le guide P2.13
# l'utilisait comme tel (bf.criticality_raw) sans qu'aucun code ne le promeuve jamais hors de
# attributes (JSON) --- même catégorie de bug que port_22_exposed/is_admin avant lui (DEC-004/006).
# Corrigé en promouvant criticality_raw dans NATIVE_PROMOTED_KEYS (packages/graph/writer.py).
#
# DEC-011 : filtre élargi à SUPPORTS *et* DEPENDS_ON. Le guide attendait un mapping
# cmdb_rel_ci -> SUPPORTS ; vérifié sur le PDI réel de Lara (dev421064), aucun des 10 types
# de relation cmdb_rel_ci réels ne s'appelle "Supports" (le plus proche est
# "Depends on::Used by", déjà le mapping par défaut de ServiceNowMapper.map_relationship,
# DEC-009). Inventer une correspondance type-par-type vers SUPPORTS sans preuve que
# ServiceNow la documente ainsi serait une supposition non vérifiée -- la règle accepte donc
# le DEPENDS_ON réel du CMDB au même titre que le SUPPORTS du CSV manuel (P1.16) : les deux
# expriment la même réalité de risque (un tiers dont dépend une fonction métier critique).
DORA_CONCENTRATION_001 = RuleSpec(
    rule_id="DORA-CONCENTRATION-001",
    severity="HIGH",
    title="Risque de concentration ICT tiers (DORA Art. 29)",
    description=(
        "Un prestataire tiers supporte (SUPPORTS) ou est requis par (DEPENDS_ON) "
        "3 fonctions ou processus métier critiques ou plus."
    ),
    remediation_hint=(
        "Évaluer une stratégie de diversification ou documenter un plan de continuité "
        "spécifique pour ce prestataire."
    ),
    cypher="""
MATCH (tp:CuzNode {tenant_id: $tenant_id, node_type: 'THIRD_PARTY'})
MATCH (tp)-[r:CUZ_EDGE]->(bf:CuzNode)
WHERE r.edge_type IN ['SUPPORTS', 'DEPENDS_ON']
  AND bf.node_type IN ['BUSINESS_FUNCTION', 'BUSINESS_PROCESS']
  AND bf.criticality_raw IN ['critical', 'high']
WITH tp, count(bf) AS critical_functions_count, collect(bf.name) AS function_names
WHERE critical_functions_count >= 3
RETURN [tp.id] AS node_ids, [tp.name] AS node_names, critical_functions_count, function_names
""",
)

RULES = [make_rule(DORA_THIRD_PARTY_001), make_rule(DORA_CONCENTRATION_001)]
