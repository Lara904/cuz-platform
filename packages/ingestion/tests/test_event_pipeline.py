# packages/ingestion/tests/test_event_pipeline.py
import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from packages.core.models.events import EventType, RawEvent
from packages.ingestion.event_pipeline import EventPipeline


class FakeProducer:
    def __init__(self) -> None:
        self.events: list[RawEvent] = []
        self.flushed = 0

    def publish(self, event: RawEvent) -> None:
        self.events.append(event)

    def flush(self) -> None:
        self.flushed += 1


def _event(i: int, source: str = "kubernetes", age_s: float = 0.0) -> RawEvent:
    return RawEvent(
        event_id=f"{source}-{i}",
        tenant_id="acmecorp",
        source=source,
        event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(UTC) - timedelta(seconds=age_s),
        raw_data={},
    )


class FiniteConnector:
    def __init__(self, source: str, n: int = 100, age_s: float = 0.0) -> None:
        self.source, self.n, self.age_s = source, n, age_s

    async def subscribe_events(self):
        for i in range(self.n):
            yield _event(i, self.source, self.age_s)


class FlakyConnector:
    """Plante deux fois avant de produire : le superviseur doit le relancer."""

    def __init__(self) -> None:
        self.attempts = 0

    async def subscribe_events(self):
        self.attempts += 1
        if self.attempts <= 2:
            raise ConnectionError("watch coupé")
        yield _event(self.attempts, "kubernetes")
        await asyncio.sleep(3600)


class BlockingConnector:
    async def subscribe_events(self):
        yield _event(0, "cloud_detection")
        await asyncio.sleep(3600)


@pytest.mark.asyncio
async def test_run_connector_stream_publishes_100_events_and_p95_under_30s():
    producer = FakeProducer()
    pipeline = EventPipeline({"kubernetes": FiniteConnector("kubernetes", 100, age_s=5)}, producer)
    await pipeline._run_connector_stream("kubernetes", pipeline.connectors["kubernetes"])
    assert len(producer.events) == 100 and pipeline.published["kubernetes"] == 100
    assert 5 <= pipeline.measure_p95_latency() < 30


def test_p95_is_nearest_rank_and_empty_is_zero():
    pipeline = EventPipeline({}, FakeProducer())
    assert pipeline.measure_p95_latency() == 0.0
    pipeline._latencies["k"] = [float(i) for i in range(1, 101)]  # 1..100 s
    assert pipeline.measure_p95_latency("k") == 95.0  # rang 95, pas 96
    assert pipeline.measure_p95_latency() == 95.0


@pytest.mark.asyncio
async def test_failing_stream_is_restarted_without_stopping_the_others():
    producer = FakeProducer()
    flaky = FlakyConnector()
    pipeline = EventPipeline(
        {"kubernetes": flaky, "cloud_detection": BlockingConnector()},
        producer,
        backoff_seconds=0.01,
        max_backoff_seconds=0.02,
    )
    task = asyncio.create_task(pipeline.run())
    for _ in range(200):  # attend que les deux flux aient publié
        if pipeline.published["kubernetes"] and pipeline.published["cloud_detection"]:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert flaky.attempts == 3 and pipeline.restarts["kubernetes"] == 2
    assert pipeline.published["cloud_detection"] == 1  # jamais interrompu par la panne de l'autre
    assert producer.flushed == 1  # flush à l'arrêt : rien de perdu


@pytest.mark.asyncio
async def test_finished_stream_is_relaunched():
    producer = FakeProducer()
    pipeline = EventPipeline(
        {"kubernetes": FiniteConnector("kubernetes", 3)},
        producer,
        backoff_seconds=0.01,
        max_backoff_seconds=0.01,
    )
    task = asyncio.create_task(pipeline.run())
    for _ in range(200):
        if pipeline.published["kubernetes"] >= 6:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pipeline.published["kubernetes"] >= 6
