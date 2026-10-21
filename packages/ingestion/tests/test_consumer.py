# packages/ingestion/tests/test_consumer.py
# Tests du PipelineConsumer via process() : idempotence, DLQ, publication
# sur cuz.normalized. Aucun broker Kafka requis (producers mockés).
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from packages.core.models.events import EventType, RawEvent
from packages.ingestion import consumer as consumer_module
from packages.ingestion.consumer import PipelineConsumer

TENANT = "acmecorp"


@pytest.fixture(autouse=True)
def _clear_seen_ids():
    consumer_module.SEEN_EVENT_IDS.clear()
    yield
    consumer_module.SEEN_EVENT_IDS.clear()


def _raw_bytes(event_id: str | None = None) -> bytes:
    raw = RawEvent(
        event_id=event_id or str(uuid.uuid4()),
        tenant_id=TENANT,
        source="servicenow",
        event_type=EventType.NODE_CREATED,
        timestamp=datetime.now(UTC),
        raw_data={"table": "cmdb_ci_server", "record": {"sys_id": "dup-01", "name": "srv"}},
    )
    return raw.model_dump_json().encode()


def _consumer() -> PipelineConsumer:
    pc = PipelineConsumer()
    pc.dlq_producer = MagicMock()
    pc.normalized_producer = MagicMock()
    return pc


def test_idempotence_100_duplicates_produce_one_event():
    """100 copies du même event_id → 1 seul NormalizedEvent émis."""
    pc = _consumer()
    emitted = []
    raw = _raw_bytes(event_id="dup-event")

    statuses = [pc.process(TENANT, raw, on_normalized=emitted.append) for _ in range(100)]

    assert statuses[0] == "processed"
    assert statuses[1:] == ["duplicate"] * 99
    assert len(emitted) == 1
    pc.dlq_producer.produce.assert_not_called()


def test_default_output_publishes_to_normalized_topic():
    pc = _consumer()
    assert pc.process(TENANT, _raw_bytes()) == "processed"
    topic = pc.normalized_producer.produce.call_args.kwargs["topic"]
    assert topic == f"cuz.normalized.{TENANT}"


def test_parse_error_goes_to_dlq():
    pc = _consumer()
    assert pc.process(TENANT, b"not json") == "parse_error"
    topic = pc.dlq_producer.produce.call_args.args[0]
    assert topic == f"cuz.graph.mutations.{TENANT}.dlq"


def test_normalize_failure_retries_then_dlq():
    pc = _consumer()
    pc.normalizer.normalize = MagicMock(side_effect=RuntimeError("boom"))

    assert pc.process(TENANT, _raw_bytes()) == "normalize_error"
    assert pc.normalizer.normalize.call_count == pc.max_retries
    pc.dlq_producer.produce.assert_called_once()
    headers = pc.dlq_producer.produce.call_args.kwargs["headers"]
    assert headers[0][0] == "reason"
    assert headers[0][1].startswith(b"normalize_error:")
