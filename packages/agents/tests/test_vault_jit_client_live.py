# packages/agents/tests/test_vault_jit_client_live.py
"""Test live de VaultJITClient contre un vrai Vault dev local.

Prérequis (voir infra/vault/policies/ et scripts/setup_vault.py) :
    docker compose -f infra/docker/docker-compose.yml up -d vault
    python scripts/setup_vault.py

Ignoré automatiquement si Vault n'est pas joignable (packages/agents/conftest.py).
"""

import hvac
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

    # Vérifié contre un vrai Vault (pas supposé) : revoke_accessor est idempotent côté
    # Vault --- révoquer un accessor déjà révoqué réussit à nouveau silencieusement
    # (204), il ne lève jamais. C'est voulu : un appel réseau redondant depuis le finally
    # d'un agent (RÈGLE 6) ne doit jamais faire planter l'appelant.
    assert client.revoke(credential["lease_id"]) is True

    # Ce qui doit réellement être vrai après révocation : le token lui-même n'est plus
    # utilisable --- c'est ça, et pas le code de retour de revoke(), qui prouve la révocation.
    with pytest.raises(hvac.exceptions.Forbidden):
        client.client.auth.token.lookup(credential["client_token"])


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
