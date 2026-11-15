# infra/vault/policies/cuz-agent-k8s.hcl
# Policy Vault pour KubernetesAgent (P2.11, vault_role = "cuz-agent-k8s").
# Voir cuz-agent-iam.hcl pour le raisonnement complet (droits minimaux, RÈGLE 6).
#
# Rappel (DECISIONS.md, DEC-006) : cette policy existe et le mécanisme JIT fonctionne pour
# ce rôle, mais K8S-PRIV-001 (seule règle gérée par KubernetesAgent) est Tier 2, pas Tier 1
# --- remediate() refuse donc systématiquement ce finding tant qu'un chemin de validation
# Tier 2 (jumeau, Phase 3) n'existe pas. Le token JIT ne sera jamais réellement émis en
# usage normal avant cela.
path "cuz/agents/k8s/*" {
  capabilities = ["read"]
}
