# packages/detection/rules/iac.py
from packages.detection.rules import RuleSpec, make_rule

# Une ressource IaC est présente dans le réel si :
# - STORAGE : un nœud réel de même nom existe (hors source terraform) ;
# - CONTAINER (Deployment) : un pod réel frais a pour owner ce nom de Deployment.
# Filtres natifs uniquement : iac_managed, owner_deployment, freshness_score, node_type.
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
    MATCH (real:CuzNode {tenant_id: $tenant_id})
    WHERE real.id <> r.id
      AND coalesce(real.iac_managed, false) = false
      AND real.freshness_score >= 0.8
      AND (
        (r.node_type = 'STORAGE' AND real.node_type = 'STORAGE' AND real.name = r.name)
        OR
        (r.node_type = 'CONTAINER' AND real.node_type = 'CONTAINER'
         AND real.owner_deployment = r.name)
      )
  }
RETURN [r.id] AS node_ids, [r.name] AS node_names
""",
)

RULES = [make_rule(IAC_DRIFT_001)]
