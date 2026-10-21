# packages/ingestion/tests/test_reconcile.py
import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from packages.core.models.enums import NodeType
from packages.detection import freshness_decay
from packages.ingestion import reconcile
from packages.ingestion.reconcile import SOURCE_KEYS


class _FakeConnector:
    def __init__(self, events=None, fail=False):
        self.events = events or []
        self.fail = fail

    async def test_connection(self):
        if self.fail:
            raise ConnectionError("source injoignable")
        return True

    async def pull_full(self):
        return self.events


class _FakeProducer:
    published: list = []

    def __init__(self, *a, **kw):
        pass

    def publish(self, raw):
        _FakeProducer.published.append(raw)

    def flush(self):
        pass


def test_reconcile_publishes_all_raw_events(monkeypatch):
    _FakeProducer.published = []
    monkeypatch.setattr(reconcile, "build_connectors",
                        lambda t: {"servicenow": _FakeConnector(events=["a", "b", "c"])})
    monkeypatch.setattr(reconcile, "EventProducer", _FakeProducer)
    assert asyncio.run(reconcile.reconcile("servicenow", "acmecorp")) == 3
    assert _FakeProducer.published == ["a", "b", "c"]


def test_reconcile_failure_raises_and_publishes_nothing(monkeypatch):
    _FakeProducer.published = []
    monkeypatch.setattr(reconcile, "build_connectors",
                        lambda t: {"servicenow": _FakeConnector(fail=True)})
    monkeypatch.setattr(reconcile, "EventProducer", _FakeProducer)
    with pytest.raises(ConnectionError):
        asyncio.run(reconcile.reconcile("servicenow", "acmecorp"))
    assert _FakeProducer.published == []


def test_unconfigured_source_raises(monkeypatch):
    monkeypatch.setattr(reconcile, "build_connectors", lambda t: {})
    with pytest.raises(RuntimeError, match="non configuré"):
        asyncio.run(reconcile.reconcile("gitea", "acmecorp"))


def test_all_cronjob_sources_have_a_connector_key():
    assert {"servicenow", "entra_id", "gitea"} <= set(SOURCE_KEYS)


def test_decayed_node_recomputes_freshness_from_last_seen():
    now = datetime.now(UTC)
    old = (now - timedelta(days=1)).isoformat()  # USER : demi-vie 1 jour → ~0.5
    row = {"id": "u1", "tenant_id": "acmecorp", "node_type": NodeType.USER.value,
           "name": "djanaD", "external_id": "e", "external_ids": {}, "confidence_score": 0.95,
           "sources": ["entra_id"], "created_at": old, "last_seen": old,
           "attributes": "{\"has_mfa\": false}", "tags": "{}"}
    node = freshness_decay.decayed_node(row, now)
    assert 0.45 <= node.freshness_score <= 0.55
    assert node.confidence_score == 0.95
    assert node.attributes == {"has_mfa": False}
