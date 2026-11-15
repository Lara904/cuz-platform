# packages/agents/conftest.py
"""Test live de VaultJITClient : marker `live_integration("vault")`.

Même principe que packages/connectors/conftest.py (Phase 1/2) : un test marqué
`@pytest.mark.live_integration("vault")` interroge un VRAI serveur Vault (dev local,
cf. infra/docker/docker-compose.yml + scripts/setup_vault.py). Service injoignable -> test
ignoré avec la raison affichée (`pytest -rs`) ; service joignable -> le test s'exécute et
ses échecs restent des échecs. CUZ_REQUIRE_LIVE=1 transforme "injoignable" en échec.
"""

import os
import socket
from urllib.parse import urlparse

import pytest

_reachability: dict[tuple[str, int], str | None] = {}


def _vault_endpoint() -> tuple[str, int]:
    parsed = urlparse(os.getenv("VAULT_ADDR", "http://localhost:8200"))
    return parsed.hostname or "localhost", parsed.port or 8200


def _unreachable_reason(endpoint: tuple[str, int], timeout: float = 3.0) -> str | None:
    if endpoint not in _reachability:
        try:
            socket.create_connection(endpoint, timeout=timeout).close()
            _reachability[endpoint] = None
        except OSError as exc:
            _reachability[endpoint] = f"{type(exc).__name__}: {exc}"
    return _reachability[endpoint]


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    marker = item.get_closest_marker("live_integration")
    if marker is None or not marker.args or marker.args[0] != "vault":
        return
    endpoint = _vault_endpoint()
    reason = _unreachable_reason(endpoint)
    if reason is None:
        return
    message = f"vault injoignable ({endpoint[0]}:{endpoint[1]}) : {reason}"
    if os.getenv("CUZ_REQUIRE_LIVE") == "1":
        pytest.fail(f"{message} — CUZ_REQUIRE_LIVE=1", pytrace=False)
    pytest.skip(f"{message} — test live ignoré")
