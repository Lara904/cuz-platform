"""
setup_vault.py — Enregistre les 3 policies Vault des agents P2.11 (IAM, Network,
Kubernetes) sur un Vault dev local.

Prérequis :
    docker compose -f infra/docker/docker-compose.yml up -d vault
    .env contient VAULT_ADDR (défaut http://localhost:8200) et VAULT_TOKEN
    (le VAULT_DEV_ROOT_TOKEN_ID du docker-compose, cuz-dev-root-token par défaut)

Usage :
    python scripts/setup_vault.py
"""

import os
from pathlib import Path

import hvac
from dotenv import load_dotenv

load_dotenv()

POLICIES_DIR = Path(__file__).resolve().parent.parent / "infra" / "vault" / "policies"

# nom de policy Vault == vault_role de l'agent (packages/agents/*.py)
POLICIES = {
    "cuz-agent-iam": POLICIES_DIR / "cuz-agent-iam.hcl",
    "cuz-agent-network": POLICIES_DIR / "cuz-agent-network.hcl",
    "cuz-agent-k8s": POLICIES_DIR / "cuz-agent-k8s.hcl",
}


def main() -> None:
    addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
    token = os.environ.get("VAULT_TOKEN", "cuz-dev-root-token")

    print("=== Setup Vault --- policies agents P2.11 ===")
    print(f"Connexion : {addr}")

    client = hvac.Client(url=addr, token=token)
    if not client.is_authenticated():
        print(f"\nConnexion échouée. Vérifie VAULT_ADDR/VAULT_TOKEN dans .env (addr={addr}).")
        raise SystemExit(1)
    print("Authentifié sur Vault (token root dev).")

    for name, path in POLICIES.items():
        policy_hcl = path.read_text()
        client.sys.create_or_update_policy(name=name, policy=policy_hcl)
        print(f"  ✅ Policy '{name}' enregistrée ({path.name})")

    print("\n── Vérification ──")
    registered = client.sys.list_policies()["data"]["policies"]
    for name in POLICIES:
        status = "présente" if name in registered else "MANQUANTE"
        print(f"  {name} : {status}")

    print("\n=== Terminé ===")
    print("P2.11 : VaultJITClient peut maintenant émettre des tokens JIT scopés par ces policies.")


if __name__ == "__main__":
    main()
