# packages/detection/rules/iam.py
from packages.detection.rules import RuleSpec, make_rule

IAM_001 = RuleSpec(
    rule_id="IAM-001",
    severity="HIGH",
    title="Identité humaine sans MFA",
    description="Un compte utilisateur actif n'a pas de MFA configuré.",
    remediation_hint="Imposer l'enregistrement MFA (Conditional Access) pour ce compte.",
    cypher="""
MATCH (u:CuzNode {tenant_id: $tenant_id, node_type: 'USER'})
WHERE u.has_mfa = false AND u.account_enabled = true
RETURN [u.id] AS node_ids, [u.name] AS node_names
""",
)

# Dépend de HAS_ROLE / ALLOWS, non produites en Phase 1 : ne matchera pas
# tant que P2.1 (Kubernetes / IAM cloud) n'est pas livré.
OAUTH_LATERAL_001 = RuleSpec(
    rule_id="OAUTH-LATERAL-001",
    severity="HIGH",
    title="Service account OAuth vers données PII",
    description="Un service account accède à un stockage contenant des PII.",
    remediation_hint="Restreindre le rôle du service account au strict nécessaire.",
    cypher="""
MATCH (sa:CuzNode {tenant_id: $tenant_id, node_type: 'SERVICE_ACCOUNT'})
      -[:CUZ_EDGE {edge_type: 'HAS_ROLE'}]->(r:CuzNode)
      -[:CUZ_EDGE {edge_type: 'ALLOWS'}]->(bucket:CuzNode {node_type: 'STORAGE'})
WHERE bucket.contains_pii = true
RETURN [sa.id, bucket.id] AS node_ids, [sa.name, bucket.name] AS node_names
""",
)

RULES = [make_rule(IAM_001), make_rule(OAUTH_LATERAL_001)]
