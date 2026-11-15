# infra/vault/policies/cuz-agent-iam.hcl
# Policy Vault pour IAMAgent (P2.11, vault_role = "cuz-agent-iam").
#
# Droits minimaux (RÈGLE 6) : AcmeCorp n'a aucun cloud réel (cf. DEC-004/DEC-005), donc ce
# policy n'autorise aujourd'hui aucun accès à un secret réel. Il existe pour que le token
# JIT émis par VaultJITClient porte une identité scopée, nommée et auditable, distincte des
# deux autres agents --- indépendamment de ce qu'il protège concrètement pour l'instant.
# À étendre avec de vrais chemins (ex. secret/aws/iam/*) le jour où un cloud réel existe.
path "cuz/agents/iam/*" {
  capabilities = ["read"]
}
