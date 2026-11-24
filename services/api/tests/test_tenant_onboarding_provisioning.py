# services/api/tests/test_tenant_onboarding_provisioning.py
"""Unitaires des 2 étapes de provisioning réel de tenant_onboarding.py (namespace
k3d, policy Vault) — mockées au niveau du client (kubernetes.client.CoreV1Api,
hvac.Client), jamais au niveau de la fonction elle-même : on veut vérifier que
la fonction appelle réellement l'API, pas supposer qu'elle le fait."""

from typing import Any

from services.api.routers.tenant_onboarding import _provision_k8s_namespace, _provision_vault_role


def test_provision_namespace_skipped_without_kubeconfig(monkeypatch):
    monkeypatch.delenv("KUBECONFIG_PATH", raising=False)
    step = _provision_k8s_namespace("acmecorp-pilot")
    assert step.status == "skipped"


def test_provision_namespace_creates_real_namespace(monkeypatch, tmp_path):
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG_PATH", str(kubeconfig))

    created: dict[str, Any] = {}

    class _CoreV1Api:
        def create_namespace(self, body: Any) -> None:
            created["name"] = body.metadata.name

    monkeypatch.setattr("kubernetes.config.load_kube_config", lambda config_file=None: None)
    monkeypatch.setattr("kubernetes.client.CoreV1Api", _CoreV1Api)

    step = _provision_k8s_namespace("acmecorp-pilot")
    assert step.status == "done"
    assert created["name"] == "acmecorp-pilot"


def test_provision_namespace_already_exists_is_idempotent(monkeypatch, tmp_path):
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG_PATH", str(kubeconfig))

    from kubernetes.client.exceptions import ApiException

    class _CoreV1Api:
        def create_namespace(self, body: Any) -> None:
            raise ApiException(status=409, reason="AlreadyExists")

    monkeypatch.setattr("kubernetes.config.load_kube_config", lambda config_file=None: None)
    monkeypatch.setattr("kubernetes.client.CoreV1Api", _CoreV1Api)

    step = _provision_k8s_namespace("acmecorp-pilot")
    assert step.status == "done"  # 409 = déjà existant : succès, pas un échec


def test_provision_namespace_reports_real_failure(monkeypatch, tmp_path):
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG_PATH", str(kubeconfig))

    from kubernetes.client.exceptions import ApiException

    class _CoreV1Api:
        def create_namespace(self, body: Any) -> None:
            raise ApiException(status=403, reason="Forbidden")

    monkeypatch.setattr("kubernetes.config.load_kube_config", lambda config_file=None: None)
    monkeypatch.setattr("kubernetes.client.CoreV1Api", _CoreV1Api)

    step = _provision_k8s_namespace("acmecorp-pilot")
    assert step.status == "failed"  # jamais "done" sur une vraie erreur


def test_provision_vault_role_skipped_without_config(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    step = _provision_vault_role("acmecorp-pilot")
    assert step.status == "skipped"


def test_provision_vault_role_creates_real_policy(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://localhost:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    created: dict[str, str] = {}

    class _Sys:
        def create_or_update_policy(self, name: str, policy: str) -> None:
            created["name"] = name
            created["policy"] = policy

    class _FakeClient:
        def __init__(self, url: str, token: str) -> None:
            self.sys = _Sys()

    monkeypatch.setattr("hvac.Client", _FakeClient)

    step = _provision_vault_role("acmecorp-pilot")
    assert step.status == "done"
    assert created["name"] == "cuz-tenant-acmecorp-pilot"
    assert "cuz/tenants/acmecorp-pilot/*" in created["policy"]
