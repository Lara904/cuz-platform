# packages/agents/tests/test_jit_agents.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
        await agent.remediate(make_finding("NET-SSH-OPEN-001"))

    client.revoke.assert_called_once_with("lease-1")


@pytest.mark.asyncio
async def test_network_agent_privatizes_bucket_via_minio():
    """DEC-006 : STORAGE-PUBLIC-001 appelle réellement l'API MinIO (plus un stub)."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-2"}
    audit = MagicMock()
    minio_client = MagicMock()
    agent = NetworkAgent(vault_client=client, audit_sink=audit, minio_client=minio_client)

    result = await agent.remediate(make_finding("STORAGE-PUBLIC-001"))

    assert result["action"] == "bucket_privatized"
    assert result["bucket"] == "srv-01"
    minio_client.delete_bucket_policy.assert_called_once_with("srv-01")
    client.revoke.assert_called_once_with("lease-2")


@pytest.mark.asyncio
async def test_network_agent_without_minio_client_refuses_explicitly():
    """Pas de faux succès : sans client MinIO configuré, on refuse plutôt que de prétendre
    avoir agi (c'est précisément l'écart que corrige DEC-006 par rapport au stub d'origine)."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-x"}
    agent = NetworkAgent(vault_client=client, audit_sink=MagicMock())

    with pytest.raises(RuntimeError):
        await agent.remediate(make_finding("STORAGE-PUBLIC-001"))


@pytest.mark.asyncio
async def test_network_agent_closes_ssh_via_direct_commit():
    """DEC-006 : NET-SSH-OPEN-001 (remplace NET-001, qui ne peut jamais matcher un actif
    réel --- cf. module docstring) commit directement sur Gitea via apply_direct()."""
    from packages.remediation.gitops_pr_generator import DirectApplyResult

    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-3"}
    gitops = MagicMock()
    gitops.apply_direct = AsyncMock(
        return_value=DirectApplyResult(file_path="network.tf", asset="srv-01", commit_sha="abc123")
    )
    agent = NetworkAgent(vault_client=client, audit_sink=MagicMock(), gitops=gitops)

    result = await agent.remediate(make_finding("NET-SSH-OPEN-001"))

    assert result["action"] == "security_group_rule_closed"
    assert result["commit_sha"] == "abc123"
    gitops.apply_direct.assert_called_once()


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
async def test_iam_agent_cis011_applies_direct_commit():
    """DEC-006 : CIS-011 commit directement sur Gitea via apply_direct() (opérationnel)."""
    from packages.remediation.gitops_pr_generator import DirectApplyResult

    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-4"}
    gitops = MagicMock()
    gitops.apply_direct = AsyncMock(
        return_value=DirectApplyResult(file_path="iam.tf", asset="srv-01", commit_sha="def456")
    )
    agent = IAMAgent(vault_client=client, audit_sink=MagicMock(), gitops=gitops)

    result = await agent.remediate(make_finding("CIS-011"))

    assert result["action"] == "permanent_admin_role_revoked"
    assert result["commit_sha"] == "def456"


@pytest.mark.asyncio
async def test_iam_agent_iam001_without_graph_client_refuses_explicitly():
    """Pas de faux succès : sans client Graph configuré (Policy.ReadWrite.ConditionalAccess
    pas encore accordée), on refuse plutôt que de prétendre "mfa_enforced" comme l'ancien
    stub --- même logique que NetworkAgent sans client MinIO."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-5"}
    agent = IAMAgent(vault_client=client, audit_sink=MagicMock())

    with pytest.raises(RuntimeError):
        await agent.remediate(make_finding("IAM-001"))

    # RÈGLE 6 : même un refus en cours d'exécution révoque le credential déjà émis.
    client.revoke.assert_called_once_with("lease-5")


@pytest.mark.asyncio
async def test_iam_agent_iam001_creates_scoped_conditional_access_policy():
    """DEC-006 : IAM-001 opérationnel --- une policy CA dédiée, scopée à l'utilisateur
    unique du finding (jamais "All users"), créée via GraphConditionalAccessClient."""
    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-6"}
    graph_client = MagicMock()
    graph_client.find_user_id_by_display_name = AsyncMock(return_value="entra-obj-123")
    graph_client.create_mfa_policy_for_user = AsyncMock(
        return_value={"id": "ca-pol-1", "displayName": "cuz-jit-mfa-entra-obj-123"}
    )
    agent = IAMAgent(vault_client=client, audit_sink=MagicMock(), graph_client=graph_client)

    result = await agent.remediate(make_finding("IAM-001"))

    assert result["action"] == "conditional_access_mfa_policy_created"
    assert result["policy_id"] == "ca-pol-1"
    graph_client.find_user_id_by_display_name.assert_called_once_with("srv-01")
    graph_client.create_mfa_policy_for_user.assert_called_once_with("entra-obj-123")
    client.revoke.assert_called_once_with("lease-6")


@pytest.mark.asyncio
async def test_iam_agent_iam001_refuses_protected_display_name_without_calling_graph():
    """Garde-fou spécifique DEC-006 : un compte listé comme protégé (admin/break-glass)
    n'est jamais ciblé, même si le finding le désigne --- refus avant tout appel Graph."""
    client = MagicMock()
    graph_client = MagicMock()
    graph_client.find_user_id_by_display_name = AsyncMock()
    graph_client.create_mfa_policy_for_user = AsyncMock()
    agent = IAMAgent(
        vault_client=client,
        audit_sink=MagicMock(),
        graph_client=graph_client,
        protected_display_names=frozenset({"srv-01"}),
    )

    with pytest.raises(PermissionError):
        await agent.remediate(make_finding("IAM-001"))

    graph_client.find_user_id_by_display_name.assert_not_called()
    graph_client.create_mfa_policy_for_user.assert_not_called()


@pytest.mark.asyncio
async def test_iam_agent_iam001_refuses_when_user_ambiguous_or_not_found():
    """Jamais d'action sur une cible incertaine : 0 ou plusieurs comptes portant ce nom
    dans Entra ID -> refus fail-safe, pas de création de policy."""
    client = MagicMock()
    graph_client = MagicMock()
    graph_client.find_user_id_by_display_name = AsyncMock(return_value=None)
    graph_client.create_mfa_policy_for_user = AsyncMock()
    agent = IAMAgent(vault_client=client, audit_sink=MagicMock(), graph_client=graph_client)

    with pytest.raises(RuntimeError):
        await agent.remediate(make_finding("IAM-001"))

    graph_client.create_mfa_policy_for_user.assert_not_called()


@pytest.mark.asyncio
async def test_kubernetes_agent_refuses_tier2_finding_without_cluster_configured():
    """DEC-006 : K8S-PRIV-001 est Tier 2 (tier_classifier.py), pas Tier 1 --- can_handle()
    est vrai (la règle est dans le périmètre de l'agent) mais remediate() refuse tant que
    le garde-fou (_twin_check) échoue. Sans cluster configuré, il échoue toujours :
    comportement inchangé par rapport à avant DEC-006."""
    client = MagicMock()
    audit = MagicMock()
    agent = KubernetesAgent(vault_client=client, audit_sink=audit)

    finding = make_finding("K8S-PRIV-001")
    assert agent.can_handle(finding) is True

    with pytest.raises(PermissionError):
        await agent.remediate(finding)

    client.acquire_jit_credential.assert_not_called()


def _fake_pod(name: str = "srv-01", namespace: str = "default", owned: bool = True):
    containers = [SimpleNamespace(name="app")]
    owner_refs = [SimpleNamespace(kind="ReplicaSet", name="api-7f9c8d")] if owned else []
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace, owner_references=owner_refs),
        spec=SimpleNamespace(containers=containers),
    )


@pytest.mark.asyncio
async def test_kubernetes_agent_twin_check_passes_and_patches_owning_deployment():
    """DEC-006 : garde-fou minimal réel --- un dry-run qui réussit contre l'API Kubernetes
    autorise le Tier 2, et l'exécution patche le Deployment propriétaire (jamais le Pod,
    dont le securityContext est immuable --- cf. module docstring)."""
    pod = _fake_pod()
    core_v1 = MagicMock()
    core_v1.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[pod])
    apps_v1 = MagicMock()

    client = MagicMock()
    client.acquire_jit_credential.return_value = {"lease_id": "lease-6"}
    agent = KubernetesAgent(
        vault_client=client, audit_sink=MagicMock(), core_v1=core_v1, apps_v1=apps_v1
    )

    finding = make_finding("K8S-PRIV-001")
    result = await agent.remediate(finding)

    assert result["action"] == "deployment_security_context_patched"
    assert result["deployment"] == "api"
    assert apps_v1.patch_namespaced_deployment.call_count == 2  # dry-run puis réel
    dry_run_call = apps_v1.patch_namespaced_deployment.call_args_list[0]
    assert dry_run_call.kwargs["dry_run"] == ["All"]
    real_call = apps_v1.patch_namespaced_deployment.call_args_list[1]
    assert "dry_run" not in real_call.kwargs
    client.revoke.assert_called_once_with("lease-6")


@pytest.mark.asyncio
async def test_kubernetes_agent_twin_check_refuses_bare_pod():
    """Un pod nu (pas de Deployment propriétaire) n'a pas de stratégie de correction
    déterministe sûre --- refus explicite, jamais de suppression/recréation devinée."""
    pod = _fake_pod(owned=False)
    core_v1 = MagicMock()
    core_v1.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[pod])
    apps_v1 = MagicMock()

    agent = KubernetesAgent(
        vault_client=MagicMock(), audit_sink=MagicMock(), core_v1=core_v1, apps_v1=apps_v1
    )

    with pytest.raises(PermissionError):
        await agent.remediate(make_finding("K8S-PRIV-001"))

    apps_v1.patch_namespaced_deployment.assert_not_called()


@pytest.mark.asyncio
async def test_kubernetes_agent_twin_check_refuses_when_dry_run_rejected():
    """Le dry-run réel échoue (ex. admission/RBAC) --- refus fail-safe, pas de passage en
    force vers l'exécution réelle."""
    pod = _fake_pod()
    core_v1 = MagicMock()
    core_v1.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[pod])
    apps_v1 = MagicMock()
    apps_v1.patch_namespaced_deployment.side_effect = RuntimeError("403 Forbidden")

    agent = KubernetesAgent(
        vault_client=MagicMock(), audit_sink=MagicMock(), core_v1=core_v1, apps_v1=apps_v1
    )

    with pytest.raises(PermissionError):
        await agent.remediate(make_finding("K8S-PRIV-001"))


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
