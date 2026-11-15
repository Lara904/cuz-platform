# packages/agents/tests/test_jit_agents.py
from unittest.mock import MagicMock

import pytest

from packages.agents.iam_agent import IAMAgent
from packages.agents.kubernetes_agent import KubernetesAgent
from packages.agents.network_agent import NetworkAgent
from packages.agents.vault_jit_client import VaultJITClient
from packages.detection.models import Finding, FindingStatus

TENANT = "acmecorp"


def make_finding(
    rule_id: str, confidence_score: float = 0.9, status: FindingStatus = "open"
) -> Finding:
    return Finding(
        tenant_id=TENANT,
        rule_id=rule_id,
        severity="HIGH",
        title="t",
        description="d",
        affected_nodes=["n1"],
        affected_node_names=["srv-01"],
        remediation_hint="h",
        confidence_score=confidence_score,
        status=status,
    )


def test_jit_ttl_capped_at_10_minutes():
    client = VaultJITClient(vault_addr="http://localhost:8200", vault_token="x")
    with pytest.raises(ValueError):
        client.acquire_jit_credential("cuz-agent-iam", ttl_seconds=3600)


def test_agent_rejects_unhandled_rule():
    client = MagicMock()
    audit = MagicMock()
    agent = IAMAgent(vault_client=client, audit_sink=audit)
    assert agent.can_handle(make_finding("NET-001")) is False


@pytest.mark.asyncio
async def test_credential_revoked_even_on_execution_failure():
    """RÈGLE 6 : révocation garantie même si _execute() lève une exception."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-1"}
    audit = MagicMock()

    class FailingAgent(NetworkAgent):
        async def _execute(self, finding, credential):
            raise RuntimeError("simulated failure")

    agent = FailingAgent(vault_client=client, audit_sink=audit)
    with pytest.raises(RuntimeError):
        await agent.remediate(make_finding("NET-001"))

    client.revoke.assert_called_once_with("lease-1")


@pytest.mark.asyncio
async def test_remediate_succeeds_on_tier1_high_confidence_finding():
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-2"}
    audit = MagicMock()
    agent = NetworkAgent(vault_client=client, audit_sink=audit)

    result = await agent.remediate(make_finding("STORAGE-PUBLIC-001"))

    assert result["action"] == "security_group_rule_closed_or_bucket_privatized"
    client.acquire_jit_credential.assert_called_once_with("cuz-agent-network")
    client.revoke.assert_called_once_with("lease-2")


@pytest.mark.asyncio
async def test_agent_refuses_low_confidence_finding():
    """RÈGLE 3 : confidence_score < 0.7 refuse l'automatisation, même pour une règle
    Tier 1 gérée par l'agent --- aucun credential JIT ne doit être émis."""
    client = MagicMock()
    audit = MagicMock()
    agent = IAMAgent(vault_client=client, audit_sink=audit)

    finding = make_finding("CIS-011", confidence_score=0.5)
    with pytest.raises(PermissionError):
        await agent.remediate(finding)

    client.acquire_jit_credential.assert_not_called()


@pytest.mark.asyncio
async def test_kubernetes_agent_refuses_tier2_finding_despite_handling_it():
    """DEC-006 : K8S-PRIV-001 est Tier 2 (tier_classifier.py), pas Tier 1 --- can_handle()
    est vrai (la règle est dans le périmètre de l'agent) mais remediate() doit refuser,
    RÈGLE 7 oblige, tant qu'aucun chemin de validation Tier 2 (jumeau, Phase 3) n'existe.
    Cet agent est donc code-complet mais non opérationnel sur sa cible réelle aujourd'hui."""
    client = MagicMock()
    audit = MagicMock()
    agent = KubernetesAgent(vault_client=client, audit_sink=audit)

    finding = make_finding("K8S-PRIV-001")
    assert agent.can_handle(finding) is True

    with pytest.raises(PermissionError):
        await agent.remediate(finding)

    client.acquire_jit_credential.assert_not_called()


def test_agents_have_disjoint_handled_rule_ids():
    iam = IAMAgent(vault_client=MagicMock(), audit_sink=MagicMock())
    network = NetworkAgent(vault_client=MagicMock(), audit_sink=MagicMock())
    k8s = KubernetesAgent(vault_client=MagicMock(), audit_sink=MagicMock())

    assert iam.handled_rule_ids.isdisjoint(network.handled_rule_ids)
    assert iam.handled_rule_ids.isdisjoint(k8s.handled_rule_ids)
    assert network.handled_rule_ids.isdisjoint(k8s.handled_rule_ids)


def test_no_agent_has_permanent_elevated_access():
    client = VaultJITClient(vault_addr="http://localhost:8200", vault_token="x")
    assert client.has_permanent_elevated_access() is False
