# packages/agents/tests/test_vault_jit_client_live.py
"""Test live de VaultJITClient contre un vrai Vault dev local.

Prérequis (voir infra/vault/policies/ et scripts/setup_vault.py) :
    docker compose -f infra/docker/docker-compose.yml up -d vault
    python scripts/setup_vault.py

Ignoré automatiquement si Vault n'est pas joignable (packages/agents/conftest.py).
"""

import pytest

from packages.agents.vault_jit_client import VaultJITClient


@pytest.mark.live_integration("vault")
def test_acquire_and_revoke_jit_credential_roundtrip():
    client = VaultJITClient()
    credential = client.acquire_jit_credential("cuz-agent-network", ttl_seconds=60)

    assert credential["lease_id"]
    assert credential["client_token"]
    assert credential["ttl_seconds"] <= 60

    assert client.revoke(credential["lease_id"]) is True
    # Un accessor déjà révoqué ne doit jamais faire planter l'appelant (RÈGLE 6 :
    # la révocation reste "au mieux", jamais bloquante pour le finally de l'agent).
    assert client.revoke(credential["lease_id"]) is False


@pytest.mark.live_integration("vault")
def test_jit_token_is_scoped_to_its_role_policy():
    """Le token émis pour cuz-agent-network ne doit porter QUE la policy
    cuz-agent-network --- pas d'escalade silencieuse vers un autre rôle."""
    client = VaultJITClient()
    credential = client.acquire_jit_credential("cuz-agent-network", ttl_seconds=60)
    try:
        lookup = client.client.auth.token.lookup(credential["client_token"])
        assert lookup["data"]["policies"] == ["cuz-agent-network", "default"] or set(
            lookup["data"]["policies"]
        ) == {"cuz-agent-network", "default"}
    finally:
        client.revoke(credential["lease_id"])
