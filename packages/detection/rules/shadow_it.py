# packages/detection/rules/shadow_it.py
"""SHADOW-IT-001 : tout nœud vu par une source technique mais absent de la CMDB
déclarée (ServiceNow). C'est un indicateur de couverture CMDB, pas une mesure de
complétude du SI réel : l'inconnu total est par définition non mesurable."""
from packages.detection.rules import RuleSpec, make_rule

SHADOW_IT_001 = RuleSpec(
    rule_id="SHADOW-IT-001",
    severity="MEDIUM",
    title="Actif absent de la CMDB déclarée",
    description="Cet actif est vu par une source technique mais n'apparaît pas dans ServiceNow.",
    remediation_hint=(
        "Vérifier si cet actif doit être déclaré en CMDB, ou s'il s'agit d'un composant "
        "technique interne (ex: dépendance logicielle) hors périmètre CMDB."
    ),
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE NOT 'servicenow' IN n.sources AND size(n.sources) > 0
RETURN [n.id] AS node_ids, [n.name] AS node_names
""",
)

RULES = [make_rule(SHADOW_IT_001)]
