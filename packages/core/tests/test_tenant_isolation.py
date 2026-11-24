# packages/core/tests/test_tenant_isolation.py
"""Unitaires de verify_cross_tenant_leak — mocke Neo4jClient (même pattern que
packages/detection/tests/test_runner_status.py), pas de dépendance réseau.
La vérification contre une vraie instance Neo4j (2 tenants réels, namespaces
k3d distincts) est faite en live lors de la validation P2.14 — voir
DECISIONS.md, DEC-010."""

from types import SimpleNamespace
from typing import Any

from packages.core import tenant_isolation as tenant_isolation_module
from packages.core.tenant_isolation import verify_cross_tenant_leak


class _Result:
    def __init__(self, value: int):
        self._value = value

    def single(self) -> dict[str, int]:
        return {"c": self._value}


def _driver(counts_by_tenant: dict[str, int]) -> Any:
    class _Session:
        def __enter__(self) -> "_Session":
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def run(self, _cypher: str, **kwargs: Any) -> _Result:
            tenant = kwargs.get("a") or kwargs.get("b")
            return _Result(counts_by_tenant.get(tenant, 0))

    return SimpleNamespace(session=_Session)


def test_no_leak_returns_zero(monkeypatch):
    monkeypatch.setattr(
        tenant_isolation_module.Neo4jClient,
        "get_driver",
        lambda: _driver({"acmecorp": 0, "acmecorp-pilot": 0}),
    )
    result = verify_cross_tenant_leak("acmecorp", "acmecorp-pilot")
    assert result == {
        "tenant_a": "acmecorp",
        "tenant_b": "acmecorp-pilot",
        "cross_tenant_nodes_found": 0,
    }


def test_leak_is_reported_not_hidden(monkeypatch):
    """Si l'instance Neo4j renvoyait un jour un nœud dont le tenant_id réel
    diverge de celui demandé (bug de driver, de cache, ou de migration de
    contrainte), ce test garantit que ce n'est jamais silencieusement ramené
    à 0."""
    monkeypatch.setattr(
        tenant_isolation_module.Neo4jClient,
        "get_driver",
        lambda: _driver({"acmecorp": 2, "acmecorp-pilot": 0}),
    )
    result = verify_cross_tenant_leak("acmecorp", "acmecorp-pilot")
    assert result["cross_tenant_nodes_found"] == 2
