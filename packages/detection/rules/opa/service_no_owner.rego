# packages/detection/rules/opa/service_no_owner.rego
# Propriété native owner (promue depuis attributes par le writer).
package cuz.ownership

import future.keywords.if
import future.keywords.in

deny[finding] if {
	node := input.node
	node.node_type in {"APPLICATION", "API", "THIRD_PARTY"}
	object.get(node, "owner", null) == null
	finding := {
		"rule_id": "OWN-OPA-001",
		"severity": "MEDIUM",
		"title": "Service sans owner (OPA)",
		"description": sprintf("Le service %v n'a aucun responsable identifié.", [node.name]),
		"node_id": node.id,
		"node_name": node.name,
		"remediation_hint": "Renseigner un owner (SPOC) dans la CMDB.",
	}
}
