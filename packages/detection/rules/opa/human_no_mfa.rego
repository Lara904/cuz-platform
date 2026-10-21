# packages/detection/rules/opa/human_no_mfa.rego
package cuz.iam

import future.keywords.if

deny[finding] if {
	node := input.node
	node.node_type == "USER"
	node.attributes.has_mfa == false
	node.attributes.account_enabled == true
	finding := {
		"rule_id": "IAM-OPA-001",
		"severity": "HIGH",
		"title": "Identité humaine sans MFA (OPA)",
		"description": sprintf("L'utilisateur %v n'a aucune méthode MFA enregistrée.", [node.name]),
		"node_id": node.id,
		"node_name": node.name,
		"remediation_hint": "Activer l'authentification multifacteur via Entra ID > Security > MFA.",
	}
}
