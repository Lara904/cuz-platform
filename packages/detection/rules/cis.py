# packages/detection/rules/cis.py
# CIS-001 à CIS-012 (guide V3, liste en une phrase chacune).
# Règle : uniquement des propriétés natives du graphe. Quand la propriété n'est
# produite par aucun connecteur, la règle existe mais ne matche pas (0 finding
# sur AcmeCorp) — c'est attendu. Les noms de propriétés sont ceux que la règle
# attend ; aucun n'est encore produit sauf ceux indiqués comme "natifs".
from packages.detection.rules import RuleSpec, make_rule

CIS_001 = RuleSpec(  # propriété attendue : tls_cert_expired (non produite)
    rule_id="CIS-001", severity="HIGH", title="Certificat TLS expiré",
    description="Un nœud expose un certificat TLS expiré.",
    remediation_hint="Renouveler le certificat et automatiser sa rotation.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.tls_cert_expired = true
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_002 = RuleSpec(  # critical_port_exposed : non produite
    rule_id="CIS-002", severity="HIGH", title="Port critique exposé",
    description="Un port critique (base de données, admin, RDP/SSH) est exposé publiquement.",
    remediation_hint="Fermer le port ou le restreindre à un réseau de confiance.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.critical_port_exposed = true AND n.is_public = true
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_003 = RuleSpec(  # owner : natif (promu depuis attributes)
    rule_id="CIS-003", severity="MEDIUM", title="Service sans owner",
    description="Un service ou une application n'a aucun responsable identifié.",
    remediation_hint="Renseigner un owner (SPOC) dans la CMDB.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.node_type IN ['APPLICATION', 'API', 'THIRD_PARTY'] AND n.owner IS NULL
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_004 = RuleSpec(  # freshness_score : natif (top-level)
    rule_id="CIS-004", severity="LOW", title="Nœud stale",
    description="Le nœud n'a pas été vu récemment (freshness < 0.2).",
    remediation_hint="Vérifier que la source est toujours active, ou retirer l'actif.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.freshness_score < 0.2
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_005 = RuleSpec(  # arêtes MEMBER_OF : non produites
    rule_id="CIS-005", severity="MEDIUM", title="Groupe avec membre direct (hors rôle)",
    description="Un utilisateur est membre direct d'un groupe, sans passer par un rôle.",
    remediation_hint="Attribuer les droits via un rôle, pas par appartenance directe.",
    cypher="""
MATCH (g:CuzNode {tenant_id: $tenant_id, node_type: 'GROUP'})
      <-[:CUZ_EDGE {edge_type: 'MEMBER_OF'}]-(u:CuzNode {node_type: 'USER'})
RETURN [g.id, u.id] AS node_ids, [g.name, u.name] AS node_names""",
)

CIS_006 = RuleSpec(  # permanent_credential : non produite
    rule_id="CIS-006", severity="HIGH", title="Service account avec credential permanent",
    description="Un service account détient un credential sans date d'expiration.",
    remediation_hint="Remplacer par un credential à durée limitée ou une identité managée.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'SERVICE_ACCOUNT'})
WHERE n.permanent_credential = true
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_007 = RuleSpec(  # backup_configured : non produite
    rule_id="CIS-007", severity="HIGH", title="Base de données sans backup configuré",
    description="Une base de données n'a pas de sauvegarde configurée.",
    remediation_hint="Configurer une sauvegarde planifiée et tester la restauration.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'DATABASE'})
WHERE n.backup_configured = false
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_008 = RuleSpec(  # auth_required : non produite
    rule_id="CIS-008", severity="HIGH", title="Ingress sans authentification",
    description="Un point d'entrée est exposé sans authentification.",
    remediation_hint="Imposer une authentification (OIDC, mTLS) sur l'ingress.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'API'})
WHERE n.auth_required = false
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_009 = RuleSpec(  # image_signed : non produite
    rule_id="CIS-009", severity="MEDIUM", title="Image de conteneur non signée",
    description="Une image de conteneur déployée n'est pas signée.",
    remediation_hint="Signer les images (cosign) et vérifier la signature à l'admission.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'CONTAINER'})
WHERE n.image_signed = false
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_010 = RuleSpec(  # plaintext_secret : non produite
    rule_id="CIS-010", severity="HIGH", title="Secret en clair dans les attributs",
    description="Un secret est stocké en clair dans les attributs d'un nœud.",
    remediation_hint="Déplacer le secret dans un coffre (Vault, Key Vault) et le référencer.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id})
WHERE n.plaintext_secret = true
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

CIS_011 = RuleSpec(  # is_admin + permanent : non produites
    rule_id="CIS-011", severity="HIGH", title="Rôle admin permanent",
    description="Un rôle administrateur est attribué de façon permanente, sans élévation temporaire.",
    remediation_hint="Passer à une élévation just-in-time (PIM) pour les rôles admin.",
    cypher="""
MATCH (r:CuzNode {tenant_id: $tenant_id, node_type: 'ROLE'})
WHERE r.is_admin = true AND r.permanent = true
RETURN [r.id] AS node_ids, [r.name] AS node_names""",
)

CIS_012 = RuleSpec(  # rate_limited : non produite
    rule_id="CIS-012", severity="MEDIUM", title="API exposée sans rate limiting",
    description="Une API exposée n'a aucune limitation de débit.",
    remediation_hint="Configurer un rate limiting au gateway.",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'API'})
WHERE n.is_public = true AND n.rate_limited = false
RETURN [n.id] AS node_ids, [n.name] AS node_names""",
)

RULES = [make_rule(spec) for spec in [
    CIS_001, CIS_002, CIS_003, CIS_004, CIS_005, CIS_006,
    CIS_007, CIS_008, CIS_009, CIS_010, CIS_011, CIS_012,
]]
