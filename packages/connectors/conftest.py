# packages/connectors/conftest.py
"""Tests live des connecteurs : marker `live_integration`.

Un test marqué `@pytest.mark.live_integration("<service>")` interroge un VRAI service (instance
ServiceNow, Gitea, Entra ID, MinIO). Même principe que `skip_if_instance_5xx` (Phase 1) :

- le service configuré est INJOIGNABLE (DNS, connexion refusée, délai) -> le test est ignoré, avec la
  raison affichée (`pytest -rs`) ;
- le service répond -> le test s'exécute et ses échecs restent des échecs : on ne masque jamais une
  régression de code, ni une erreur d'authentification, ni une donnée inattendue.

La vérification porte sur l'endpoint réellement configuré (variables d'environnement), pas sur
l'exception levée par le test : un bug qui fabriquerait une mauvaise URL reste un échec.

CUZ_REQUIRE_LIVE=1 transforme « injoignable » en échec, pour une exécution où la pile est censée être
démarrée (un service tombé ne doit pas passer pour un test réussi).

La CI GitHub Actions n'a accès à aucun de ces services : son job `unit-tests` exclut le marker
(`-m "not live_integration"`).
"""

import os
import socket
from collections.abc import Callable
from urllib.parse import urlparse

import pytest

Endpoint = tuple[str, int]


def _from_url(url: str) -> Endpoint:
    parsed = urlparse(url)
    return parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)


def _from_host_port(value: str) -> Endpoint:
    host, _, port = value.partition(":")
    return host, int(port or 80)


# service -> endpoint effectivement configuré (mêmes variables et valeurs par défaut que les fixtures)
LIVE_SERVICES: dict[str, Callable[[], Endpoint]] = {
    "servicenow": lambda: _from_url(
        os.getenv("SERVICENOW_URL", "https://dev353984.service-now.com")
    ),
    "gitea": lambda: _from_url(os.getenv("GITEA_URL", "http://localhost:3000")),
    "entra_id": lambda: ("login.microsoftonline.com", 443),
    "minio": lambda: _from_host_port(os.getenv("MINIO_ENDPOINT", "localhost:9000")),
}

_reachability: dict[Endpoint, str | None] = {}


def unreachable_reason(endpoint: Endpoint, timeout: float = 3.0) -> str | None:
    """None si une connexion TCP aboutit, sinon la cause (mise en cache pour la session)."""
    if endpoint not in _reachability:
        try:
            socket.create_connection(endpoint, timeout=timeout).close()
            _reachability[endpoint] = None
        except OSError as exc:  # gaierror, ConnectionRefusedError, TimeoutError...
            _reachability[endpoint] = f"{type(exc).__name__}: {exc}"
    return _reachability[endpoint]


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    marker = item.get_closest_marker("live_integration")
    if marker is None:
        return
    service = str(marker.args[0]) if marker.args else ""
    if service not in LIVE_SERVICES:
        raise pytest.UsageError(
            f"live_integration: service inconnu {service!r} (attendu : {sorted(LIVE_SERVICES)})"
        )
    host, port = LIVE_SERVICES[service]()
    reason = unreachable_reason((host, port))
    if reason is None:
        return
    message = f"{service} injoignable ({host}:{port}) : {reason}"
    if os.getenv("CUZ_REQUIRE_LIVE") == "1":
        pytest.fail(f"{message} — CUZ_REQUIRE_LIVE=1", pytrace=False)
    pytest.skip(f"{message} — test live ignoré")
