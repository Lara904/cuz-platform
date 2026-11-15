# packages/detection/rules/iac_tier1_extra.py
"""Trois règles Tier 1 complémentaires (P2.10 bis, DEC-004), sur le modèle de network.py /
iam.py : Cypher pur, filtre sur un booléen natif posé par le connecteur Terraform (P2.3,
packages/connectors/terraform/mapper.py) lors du mapping, jamais de date calculée en Cypher.

IAM-STALE-ROLE-001 et CERT-EXPIRED-001 sont classées Tier 1 (tier_classifier.py) mais ne
génèrent PAS de PR GitOps automatique (SUPPORTED_RULES de gitops_pr_generator.py) : désactiver
un rôle ou "corriger" un certificat expiré n'a pas de réécriture Terraform sûre et déterministe,
contrairement à `acl = "private"`. Seule NET-SSH-OPEN-001 a un correctif IaC vérifié (fermeture
du CIDR, voir terraform_edit.py) et figure dans SUPPORTED_RULES.
"""

from packages.detection.rules import RuleSpec, make_rule

IAM_STALE_ROLE_001 = RuleSpec(
    rule_id="IAM-STALE-ROLE-001",
    severity="MEDIUM",
    title="Rôle IAM inutilisé depuis plus de 90 jours",
    description="Un rôle IAM n'a plus été utilisé depuis plus de 90 jours.",
    remediation_hint="Vérifier qu'aucune charge de travail n'en dépend, puis désactiver ou supprimer le rôle.",
    cypher="""
MATCH (r:CuzNode {tenant_id: $tenant_id, node_type: 'ROLE'})
WHERE r.role_unused_90d = true
RETURN [r.id] AS node_ids, [r.name] AS node_names
""",
)

NET_SSH_OPEN_001 = RuleSpec(
    rule_id="NET-SSH-OPEN-001",
    severity="CRITICAL",
    title="Règle réseau avec le port 22 ouvert à 0.0.0.0/0",
    description="Une règle de security group autorise le port SSH depuis n'importe quelle adresse.",
    remediation_hint="Restreindre le CIDR de la règle (ou la fermer) via une PR GitOps (Tier 1).",
    cypher="""
MATCH (n:CuzNode {tenant_id: $tenant_id, node_type: 'NETWORK'})
WHERE n.port_22_exposed = true AND n.is_public = true
RETURN [n.id] AS node_ids, [n.name] AS node_names
""",
)

CERT_EXPIRED_001 = RuleSpec(
    rule_id="CERT-EXPIRED-001",
    severity="HIGH",
    title="Certificat expiré",
    description="Un certificat géré en IaC a dépassé sa date d'expiration (not_after).",
    remediation_hint="Renouveler le certificat hors IaC (CA/ACM) ; aucune PR automatique possible.",
    cypher="""
MATCH (c:CuzNode {tenant_id: $tenant_id, node_type: 'CERTIFICATE'})
WHERE c.cert_expired = true
RETURN [c.id] AS node_ids, [c.name] AS node_names
""",
)

RULES = [make_rule(IAM_STALE_ROLE_001), make_rule(NET_SSH_OPEN_001), make_rule(CERT_EXPIRED_001)]
