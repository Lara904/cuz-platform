# packages/detection/rules/iac.py
from packages.detection.rules import RuleSpec, make_rule

# Filtre sur la propriété native iac_managed (promue depuis tags par le writer).
# Un CONTAINS sur tags_json ne matcherait pas : json.dumps ajoute un espace après ':'.
IAC_DRIFT_001 = RuleSpec(
    rule_id="IAC-DRIFT-001",
    severity="MEDIUM",
    title="Ressource IaC absente de l'infrastructure réelle",
    description="Une ressource déclarée en IaC n'a aucun équivalent dans l'infrastructure observée.",
    remediation_hint="Vérifier si la ressource a été supprimée hors IaC, puis réconcilier l'état.",
    cypher="""
MATCH (r:CuzNode {tenant_id: $tenant_id})
WHERE r.iac_managed = true
  AND NOT EXISTS {
    MATCH (real:CuzNode {tenant_id: $tenant_id, name: r.name})
    WHERE real.id <> r.id
  }
RETURN [r.id] AS node_ids, [r.name] AS node_names
""",
)

RULES = [make_rule(IAC_DRIFT_001)]
