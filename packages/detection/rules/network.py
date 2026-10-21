# packages/detection/rules/network.py
from packages.detection.rules import RuleSpec, make_rule

NET_001 = RuleSpec(
    rule_id="NET-001",
    severity="CRITICAL",
    title="Port SSH exposé depuis Internet",
    description="Un serveur, conteneur ou cluster expose le port 22 publiquement.",
    remediation_hint="Restreindre le port 22 aux bastions via security group / firewall.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.node_type IN ['SERVER', 'CONTAINER', 'CLUSTER']
  AND n.port_22_exposed = true AND n.is_public = true
RETURN [n.id] AS node_ids, [n.name] AS node_names
""",
)

STORAGE_PUBLIC_001 = RuleSpec(
    rule_id="STORAGE-PUBLIC-001",
    severity="HIGH",
    title="Bucket de stockage accessible publiquement",
    description="Un bucket de stockage objet est accessible sans authentification.",
    remediation_hint="Désactiver l'accès public du bucket et revoir la policy.",
    cypher="""
MATCH (b:CuzNode {tenant_id: $tenant_id, node_type: 'STORAGE'})
WHERE b.is_public = true
RETURN [b.id] AS node_ids, [b.name] AS node_names
""",
)

K8S_PRIV_001 = RuleSpec(
    rule_id="K8S-PRIV-001",
    severity="HIGH",
    title="Pod Kubernetes avec contexte privilégié",
    description="Un conteneur tourne en privileged ou run_as_root.",
    remediation_hint="Retirer privileged / runAsRoot du securityContext du pod.",
    cypher="""
MATCH (p:CuzNode {tenant_id: $tenant_id, node_type: 'CONTAINER'})
WHERE p.privileged = true OR p.run_as_root = true
RETURN [p.id] AS node_ids, [p.name] AS node_names
""",
)

RULES = [make_rule(NET_001), make_rule(STORAGE_PUBLIC_001), make_rule(K8S_PRIV_001)]
