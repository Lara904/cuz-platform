# packages/detection/rules/attack_path.py
from packages.detection.rules import RuleSpec, make_rule

# Version réalisable en Phase 1 (3 maillons). La version à 5 maillons
# (ATTACK-PATH-001, jusqu'au pod et au bucket) dépend du connecteur Kubernetes (P2.1).
# Filtre sur le nom complet qs@6.5.2 (CVE-2022-24999) et non sur le seul package.
ATTACK_PATH_001_PARTIAL = RuleSpec(
    rule_id="ATTACK-PATH-001-PARTIAL",
    severity="CRITICAL",
    title="Chemin d'attaque : utilisateur sans MFA → repo → qs@6.5.2 (CVE-2022-24999)",
    description=(
        "Un utilisateur sans MFA possède un repository qui dépend de qs@6.5.2, "
        "vulnérable à CVE-2022-24999 (CVSS 9.8)."
    ),
    remediation_hint=(
        "Activer le MFA pour l'utilisateur, et mettre à jour qs vers >= 6.5.3 "
        "(ou 6.10.3+) dans le repository."
    ),
    cypher="""
MATCH (u:CuzNode {tenant_id: $tenant_id, node_type: 'USER'})
      -[:CUZ_EDGE {edge_type: 'OWNS'}]->(repo:CuzNode {node_type: 'REPOSITORY'})
      -[:CUZ_EDGE {edge_type: 'DEPENDS_ON'}]->(dep:CuzNode {node_type: 'VULNERABILITY'})
WHERE u.has_mfa = false AND dep.name = 'qs@6.5.2'
RETURN [u.id, repo.id, dep.id] AS node_ids,
       [u.name, repo.name, dep.name] AS node_names
""",
)

RULES = [make_rule(ATTACK_PATH_001_PARTIAL)]
