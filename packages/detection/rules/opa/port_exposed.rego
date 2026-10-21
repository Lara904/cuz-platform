# packages/detection/rules/opa/port_exposed.rego
# Attribut attendu : critical_port_exposed (non produit aujourd'hui) → 0 finding.
package cuz.network

import future.keywords.if
import future.keywords.in

deny[finding] if {
	node := input.node
	node.node_type in {"SERVER", "CONTAINER", "CLUSTER", "NETWORK"}
	node.attributes.critical_port_exposed == true
	node.attributes.is_public == true
	finding := {
		"rule_id": "NET-OPA-001",
		"severity": "HIGH",
		"title": "Port critique exposé publiquement (OPA)",
		"description": sprintf("Le nœud %v expose un port critique sur Internet.", [node.name]),
		"node_id": node.id,
		"node_name": node.name,
		"remediation_hint": "Fermer le port ou le restreindre à un réseau de confiance.",
	}
}
