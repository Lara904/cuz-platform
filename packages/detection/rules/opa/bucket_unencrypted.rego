# packages/detection/rules/opa/bucket_unencrypted.rego
# Attribut attendu : encrypted (non produit par le connecteur MinIO aujourd'hui) → 0 finding.
package cuz.storage

import future.keywords.if

deny[finding] if {
	node := input.node
	node.node_type == "STORAGE"
	node.attributes.encrypted == false
	finding := {
		"rule_id": "STORAGE-OPA-001",
		"severity": "HIGH",
		"title": "Bucket non chiffré (OPA)",
		"description": sprintf("Le bucket %v n'est pas chiffré au repos.", [node.name]),
		"node_id": node.id,
		"node_name": node.name,
		"remediation_hint": "Activer le chiffrement côté serveur (SSE) sur le bucket.",
	}
}
