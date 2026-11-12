# packages/detection/tests/test_runner_status.py
"""Le runner ne cache jamais une détection dégradée : erreurs remontées, findings conservés."""

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from packages.detection import runner as runner_module
from packages.detection.models import Finding
from packages.detection.opa_client import OPAPolicyError, OPAUnavailableError
from packages.detection.runner import DetectionRunner

TENANT = "acmecorp"


def _finding(rule_id: str = "IAM-001", node: str = "u1") -> Finding:
    return Finding(
        tenant_id=TENANT,
        rule_id=rule_id,
        severity="HIGH",
        title="t",
        description="d",
        affected_nodes=[node],
        affected_node_names=[node],
        remediation_hint="h",
    )


class _Session:
    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(data=lambda: [])  # aucune alerte cloud, aucune confiance à relire


def _runner(monkeypatch, rules: list[Any], opa: Any) -> DetectionRunner:
    monkeypatch.setattr(
        runner_module.Neo4jClient, "get_driver", lambda: SimpleNamespace(session=_Session)
    )
    monkeypatch.setattr(runner_module, "ALL_RULE_MODULES", [SimpleNamespace(RULES=rules)])
    runner = DetectionRunner()
    monkeypatch.setattr(runner, "run_opa", opa)
    return runner


def _rule(rule_id: str, node: str = "u1"):
    def rule(session: Any, tenant_id: str) -> list[Finding]:
        return [_finding(rule_id, node)]

    rule.__name__ = rule_id.replace("-", "_")
    return rule


def _boom(session: Any, tenant_id: str) -> list[Finding]:
    raise RuntimeError("neo4j: secret interne")


_boom.__name__ = "BOOM_001"


def test_complete_detection_has_no_errors(monkeypatch):
    runner = _runner(monkeypatch, [_rule("NET-001")], lambda t: [_finding("IAM-OPA-001")])
    findings, errors = runner.run_all_with_status(TENANT)
    assert errors == []
    assert {f.rule_id for f in findings} == {"NET-001", "IAM-OPA-001"}


def test_opa_down_is_reported_and_cypher_findings_are_kept(monkeypatch):
    def opa(tenant_id: str) -> list[Finding]:
        raise OPAUnavailableError("OPA injoignable (http://opa.interne:8181) : refused")

    runner = _runner(monkeypatch, [_rule("NET-001")], opa)
    findings, errors = runner.run_all_with_status(TENANT)
    assert errors == ["OPA : injoignable ou en erreur"]
    assert [f.rule_id for f in findings] == ["NET-001"]  # ne masque pas les autres findings


def test_opa_policy_error_is_reported_with_its_own_summary(monkeypatch):
    def opa(tenant_id: str) -> list[Finding]:
        raise OPAPolicyError("package cuz/tls indéfini")

    _, errors = _runner(monkeypatch, [], opa).run_all_with_status(TENANT)
    assert errors == ["OPA : policies absentes, refusées ou indéfinies"]


def test_partial_opa_findings_are_not_lost(monkeypatch):
    def opa(tenant_id: str) -> list[Finding]:
        raise OPAUnavailableError("coupure", [_finding("IAM-OPA-001")])

    findings, errors = _runner(monkeypatch, [], opa).run_all_with_status(TENANT)
    assert [f.rule_id for f in findings] == ["IAM-OPA-001"] and len(errors) == 1


def test_failing_cypher_rule_is_reported_not_silent(monkeypatch):
    runner = _runner(monkeypatch, [_boom, _rule("NET-001")], lambda t: [])
    findings, errors = runner.run_all_with_status(TENANT)
    assert errors == ["règle BOOM_001 en échec"]
    assert [f.rule_id for f in findings] == ["NET-001"]


def test_errors_exposed_to_the_api_leak_no_internal_detail(monkeypatch):
    def opa(tenant_id: str) -> list[Finding]:
        raise OPAUnavailableError("OPA injoignable (http://opa.interne:8181) : secret")

    _, errors = _runner(monkeypatch, [_boom], opa).run_all_with_status(TENANT)
    joined = " ".join(errors)
    assert "opa.interne" not in joined and "secret" not in joined and "8181" not in joined


def test_run_all_still_returns_findings_only_and_logs_the_degradation(monkeypatch, caplog):
    def opa(tenant_id: str) -> list[Finding]:
        raise OPAUnavailableError("OPA injoignable")

    runner = _runner(monkeypatch, [_rule("NET-001")], opa)
    with caplog.at_level(logging.ERROR, logger="packages.detection.runner"):
        findings = runner.run_all(TENANT)
    assert [f.rule_id for f in findings] == ["NET-001"]
    assert any("OPA dégradée" in r.message for r in caplog.records)


def test_non_opa_exception_in_opa_step_is_not_swallowed(monkeypatch):
    """Seule OPAError devient « dégradé » : un bug ou une panne Neo4j reste une vraie erreur."""

    def opa(tenant_id: str) -> list[Finding]:
        raise KeyError("bug")

    with pytest.raises(KeyError):
        _runner(monkeypatch, [], opa).run_all_with_status(TENANT)
