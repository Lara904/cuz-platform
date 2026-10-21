# packages/graph/tests/test_writer_delivery.py
# Garanties de livraison du writer : un échec part en DLQ, et l'offset n'est validé
# qu'après confirmation de la DLQ. Aucun Kafka ni Neo4j requis.
from unittest.mock import MagicMock

import pytest

from packages.graph.writer import GraphWriter

TENANT = "acmecorp"


def _writer(delivery_errors: int = 0) -> GraphWriter:
    w = object.__new__(GraphWriter)
    w.driver = MagicMock()
    w._pending_repos = {}
    w.owner_linker = MagicMock()
    w.producer = MagicMock()
    w.producer.flush.return_value = delivery_errors  # 0 = confirmé
    w.consumer = MagicMock()
    msg = MagicMock()
    msg.error.return_value = None
    msg.value.return_value = b'{"poison": true}'
    # Un message, puis plus rien (idle_timeout=1 → arrêt)
    w.consumer.poll.side_effect = [msg, None]
    return w


def test_failed_message_goes_to_dlq_and_offset_is_committed(monkeypatch):
    w = _writer(delivery_errors=0)
    monkeypatch.setattr(w, "process_event", MagicMock(side_effect=ValueError("boom")))
    w.run(TENANT, idle_timeout=1.0)
    topic = w.producer.produce.call_args.kwargs["topic"]
    assert topic == f"cuz.graph.mutations.{TENANT}.dlq"
    w.consumer.commit.assert_called_once()


def test_unconfirmed_dlq_stops_without_committing(monkeypatch):
    w = _writer(delivery_errors=1)
    monkeypatch.setattr(w, "process_event", MagicMock(side_effect=ValueError("boom")))
    with pytest.raises(RuntimeError, match="DLQ non confirmée"):
        w.run(TENANT, idle_timeout=1.0)
    w.consumer.commit.assert_not_called()


def test_successful_message_is_committed_without_dlq(monkeypatch):
    w = _writer()
    monkeypatch.setattr(w, "process_event", MagicMock(return_value=None))
    w.run(TENANT, idle_timeout=1.0)
    w.producer.produce.assert_not_called()
    w.consumer.commit.assert_called_once()


def test_consumer_uses_static_membership_and_short_session():
    captured = {}

    def fake_consumer(conf):
        captured.update(conf)
        return MagicMock()

    import packages.graph.writer as writer_mod
    orig = writer_mod.Consumer
    writer_mod.Consumer = fake_consumer
    try:
        writer_mod.GraphWriter.__init__(object.__new__(GraphWriter), "localhost:9092")
    finally:
        writer_mod.Consumer = orig
    assert captured["group.instance.id"]
    assert captured["session.timeout.ms"] <= 10000
