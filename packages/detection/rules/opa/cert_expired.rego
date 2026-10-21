# packages/detection/rules/opa/cert_expired.rego
# Attribut attendu : tls_cert_expired (non produit aujourd'hui) → 0 finding.
package cuz.tls

import future.keywords.if

deny[finding] if {
	node := input.node
	node.attributes.tls_cert_expired == true
	finding := {
		"rule_id": "TLS-OPA-001",
		"severity": "HIGH",
		"title": "Certificat TLS expiré (OPA)",
		"description": sprintf("Le certificat TLS de %v est expiré.", [node.name]),
		"node_id": node.id,
		"node_name": node.name,
		"remediation_hint": "Renouveler le certificat et automatiser sa rotation.",
	}
}
