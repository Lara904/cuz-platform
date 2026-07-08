# packages/core/tests/test_connector.py
"""
5 tests de contrat P0.5 — Interface IConnector et MockConnector.
Valide que tout connecteur respectant IConnector se comporte correctement.

Lancer avec : pytest packages/core/tests/test_connector.py -v
"""

import pytest

from packages.core.interfaces.mock_connector import MockConnector
from packages.core.models.events import RawEvent

# ── Contrat 1 : test_connection OK ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connector_connection_ok():
    """Un connecteur fonctionnel retourne True sur test_connection()."""
    connector = MockConnector(tenant_id="acmecorp", config={})
    result = await connector.test_connection()
    assert result is True


# ── Contrat 2 : test_connection KO ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connector_connection_failure_raises():
    """Un connecteur en échec lève une exception sur test_connection()."""
    connector = MockConnector(tenant_id="acmecorp", config={}, should_fail=True)
    with pytest.raises(ConnectionError):
        await connector.test_connection()


# ── Contrat 3 : pull_full retourne des RawEvents valides ──────────────────────


@pytest.mark.asyncio
async def test_connector_pull_returns_raw_events():
    """pull_full() retourne une liste de RawEvent avec le bon tenant_id."""
    connector = MockConnector(tenant_id="stellantis-financial", config={})
    events = await connector.pull_full()

    assert isinstance(events, list)
    assert len(events) > 0
    for event in events:
        assert isinstance(event, RawEvent)
        assert event.tenant_id == "stellantis-financial"
        assert event.source == "mock"
        assert event.event_id is not None


# ── Contrat 4 : idempotence de pull_full ──────────────────────────────────────


@pytest.mark.asyncio
async def test_connector_pull_is_idempotent():
    """Deux appels à pull_full() retournent le même nombre d'événements."""
    connector = MockConnector(tenant_id="acmecorp", config={})
    events_1 = await connector.pull_full()
    events_2 = await connector.pull_full()

    assert len(events_1) == len(events_2)


# ── Contrat 5 : subscribe_events yield des RawEvents ─────────────────────────


@pytest.mark.asyncio
async def test_connector_subscribe_yields_raw_events():
    """subscribe_events() yield des RawEvent valides avec le bon tenant_id."""
    connector = MockConnector(tenant_id="acmecorp", config={})
    events = []
    async for event in connector.subscribe_events():
        assert isinstance(event, RawEvent)
        assert event.tenant_id == "acmecorp"
        events.append(event)

    assert len(events) > 0
