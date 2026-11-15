# infra/vault/policies/cuz-agent-network.hcl
# Policy Vault pour NetworkAgent (P2.11, vault_role = "cuz-agent-network").
# Voir cuz-agent-iam.hcl pour le raisonnement complet (droits minimaux, RÈGLE 6).
path "cuz/agents/network/*" {
  capabilities = ["read"]
}
