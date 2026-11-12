# packages/detection/tests/test_mutation_consumer.py
import json
import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from confluent_kafka import KafkaError

from packages.core.models.enums import NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.models.node import CuzNode
from packages.detection.models import Finding
from packages.detection.mutation_consumer import MutationConsumer
from packages.detection.mutation_router import BatchResult

TENANT = "acmecorp"


def _event(tenant: str = TENANT, name: str = "djana.dev") -> NormalizedEvent:
    node = CuzNode(
        tenant_id=tenant,
        node_type=NodeType.USER,
        name=name,
        confidence_score=0.9,
        freshness_score=1.0,
    )
    return NormalizedEvent(
        event_id="e",
        raw_event_id="r",
        tenant_id=tenant,
        source="entra_id",
        event_type=EventType.NODE_UPDATED,
        timestamp=datetime.now(UTC),
        node=node,
    )


def _finding(node: str = "entra_id:u1", rule: str = "IAM-001") -> Finding:
    return Finding(
        tenant_id=TENANT,
        rule_id=rule,
        severity="HIGH",
        title="t",
        description="d",
        affected_nodes=[node],
        affected_node_names=[node],
        remediation_hint="h",
    )


class Msg:
    def __init__(self, value: bytes = b"", error: Any = None) -> None:
        self._value, self._error = value, error

    def value(self) -> bytes:
        return self._value

    def error(self) -> Any:
        return self._error


def _msg(event: NormalizedEvent) -> Msg:
    return Msg(event.model_dump_json().encode())


class FakeConsumer:
    def __init__(self, polls: list[Any] | None = None, batch: list[Any] | None = None) -> None:
        self.polls = list(polls or [])
        self.batch = list(batch or [])
        self.commits = 0
        self.subscribed: list[str] = []
        self.closed = False

    def subscribe(self, topics: list[str]) -> None:
        self.subscribed = topics

    def poll(self, timeout: float) -> Any:
        return self.polls.pop(0) if self.polls else None

    def consume(self, num: int, timeout: float) -> list[Any]:
        out, self.batch = self.batch[:num], self.batch[num:]
        return out

    def commit(self, asynchronous: bool = True) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


class FakeProducer:
    def __init__(self, undelivered: int = 0) -> None:
        self.sent: list[tuple[str, bytes | None, bytes, dict[str, str]]] = []
        self.undelivered = undelivered

    def produce(self, topic: str, value: bytes, key: bytes | None = None, headers: Any = None):
        self.sent.append((topic, key, value, {k: v.decode() for k, v in (headers or [])}))

    def poll(self, timeout: float) -> int:
        return 0

    def flush(self, timeout: float = 0) -> int:
        return self.undelivered

    def to(self, topic: str) -> list[tuple[str, bytes | None, bytes, dict[str, str]]]:
        return [m for m in self.sent if m[0] == topic]


class FakeRouter:
    """Rejoue des résultats scriptés ; une valeur Exception est levée."""

    def __init__(self, *results: BatchResult | Exception) -> None:
        self.results = list(results)
        self.calls: list[list[NormalizedEvent]] = []

    def run_on_mutations(self, tenant_id: str, events: list[NormalizedEvent]) -> BatchResult:
        self.calls.append(list(events))
        r = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(r, Exception):
            raise r
        return r


def _ok(*findings: Finding, rules: int = 3) -> BatchResult:
    return BatchResult(findings=list(findings), failed_rules=[], rules_run=rules)


def _consumer(router: Any, producer: FakeProducer | None = None, consumer: Any = None, **kw: Any):
    sleeps: list[float] = []
    mc = MutationConsumer(
        TENANT,
        router=router,
        consumer=consumer or FakeConsumer(),
        producer=producer or FakeProducer(),
        sleep=sleeps.append,
        **kw,
    )
    mc.sleeps = sleeps  # type: ignore[attr-defined]
    return mc


def test_findings_are_published_then_offset_committed():
    producer = FakeProducer()
    mc = _consumer(FakeRouter(_ok(_finding())), producer)
    assert mc.process_batch([_msg(_event())]) == 1
    sent = producer.to(f"cuz.findings.{TENANT}")
    assert len(sent) == 1 and sent[0][1] == b"IAM-001"
    assert json.loads(sent[0][2])["affected_nodes"] == ["entra_id:u1"]
    assert mc.consumer.commits == 1


def test_same_finding_is_not_republished_on_next_batch():
    producer = FakeProducer()
    mc = _consumer(FakeRouter(_ok(_finding())), producer)
    mc.process_batch([_msg(_event())])
    assert mc.process_batch([_msg(_event())]) == 0
    assert len(producer.to(f"cuz.findings.{TENANT}")) == 1


def test_new_finding_on_other_node_is_published():
    producer = FakeProducer()
    mc = _consumer(FakeRouter(_ok(_finding("a")), _ok(_finding("a"), _finding("b"))), producer)
    mc.process_batch([_msg(_event())])
    assert mc.process_batch([_msg(_event())]) == 1


def test_whole_batch_goes_to_router_in_one_call():
    router = FakeRouter(_ok())
    mc = _consumer(router)
    mc.process_batch([_msg(_event()) for _ in range(40)])
    assert len(router.calls) == 1 and len(router.calls[0]) == 40


def test_unparseable_message_goes_to_dlq_and_others_are_processed():
    producer = FakeProducer()
    router = FakeRouter(_ok(_finding()))
    mc = _consumer(router, producer)
    mc.process_batch([Msg(b"pas du json"), _msg(_event())])
    dlq = producer.to(f"cuz.graph.mutations.{TENANT}.dlq")
    assert len(dlq) == 1 and dlq[0][3]["reason"].startswith("detection_parse_error")
    assert len(router.calls[0]) == 1
    assert mc.consumer.commits == 1


def test_other_tenant_event_is_dlqd_and_never_evaluated():
    producer = FakeProducer()
    router = FakeRouter(_ok())
    mc = _consumer(router, producer)
    mc.process_batch([_msg(_event(tenant="other"))])
    assert producer.to(f"cuz.graph.mutations.{TENANT}.dlq")[0][3]["reason"].startswith(
        "detection_tenant_mismatch:other"
    )
    assert router.calls == []


def test_batch_with_only_bad_messages_still_commits():
    mc = _consumer(FakeRouter(_ok()))
    mc.process_batch([Msg(b"x")])
    assert mc.consumer.commits == 1


def test_failed_rule_is_retried_with_exponential_backoff_then_succeeds():
    producer = FakeProducer()
    failed = BatchResult(findings=[], failed_rules=["IAM-001"], rules_run=3)
    mc = _consumer(FakeRouter(failed, failed, _ok(_finding())), producer, retry_backoff=2.0)
    assert mc.process_batch([_msg(_event())]) == 1
    assert mc.sleeps == [2.0, 4.0]  # type: ignore[attr-defined]
    assert producer.to(f"cuz.graph.mutations.{TENANT}.dlq") == []


def test_persistent_failure_sends_batch_to_dlq_publishes_partial_and_commits():
    producer = FakeProducer()
    partial = BatchResult(findings=[_finding(rule="ATTACK-PATH-001-PARTIAL")],
                          failed_rules=["IAM-001"], rules_run=3)  # fmt: skip
    mc = _consumer(FakeRouter(partial), producer, max_retries=3)
    mc.process_batch([_msg(_event()), _msg(_event(name="b"))])
    dlq = producer.to(f"cuz.graph.mutations.{TENANT}.dlq")
    assert len(dlq) == 2
    assert all(m[3]["reason"] == "detection_failed:rules_failed:IAM-001" for m in dlq)
    assert len(producer.to(f"cuz.findings.{TENANT}")) == 1  # règles réussies non perdues
    assert mc.consumer.commits == 1  # le lot en échec ne bloque pas la partition


def test_router_exception_is_retried_then_dlqd():
    producer = FakeProducer()
    mc = _consumer(FakeRouter(RuntimeError("neo4j down")), producer, max_retries=2)
    mc.process_batch([_msg(_event())])
    dlq = producer.to(f"cuz.graph.mutations.{TENANT}.dlq")
    assert dlq[0][3]["reason"] == "detection_failed:error:neo4j down"
    assert mc.sleeps == [2.0]  # type: ignore[attr-defined]
    assert mc.consumer.commits == 1


def test_undelivered_findings_raise_and_offset_is_not_committed():
    mc = _consumer(FakeRouter(_ok(_finding())), FakeProducer(undelivered=1))
    with pytest.raises(RuntimeError):
        mc.process_batch([_msg(_event())])
    assert mc.consumer.commits == 0
    assert mc._emitted == set()  # sera republié au rejeu


def test_run_subscribes_processes_and_stops_when_idle():
    fake = FakeConsumer(polls=[_msg(_event())], batch=[_msg(_event())])
    router = FakeRouter(_ok(_finding()))
    mc = _consumer(router, consumer=fake)
    mc.run(idle_timeout=2)
    assert fake.subscribed == [f"cuz.graph.mutations.{TENANT}"]
    assert len(router.calls) == 1 and len(router.calls[0]) == 2
    assert mc.stats == {"batches": 1, "events": 2, "findings": 1, "dlq": 0}
    assert fake.closed


class _Err:
    def __init__(self, code: int) -> None:
        self._code = code

    def code(self) -> int:
        return self._code

    def __str__(self) -> str:
        return f"err{self._code}"


def test_run_survives_kafka_errors_such_as_missing_topic():
    unknown = Msg(error=_Err(KafkaError.UNKNOWN_TOPIC_OR_PART))
    eof = Msg(error=_Err(KafkaError._PARTITION_EOF))
    fake = FakeConsumer(polls=[unknown, eof, _msg(_event())])
    router = FakeRouter(_ok())
    mc = _consumer(router, consumer=fake)
    mc.run(idle_timeout=2)
    assert len(router.calls) == 1


def test_run_stops_on_event_and_closes_consumer():
    stop = threading.Event()
    stop.set()
    fake = FakeConsumer()
    _consumer(FakeRouter(_ok()), consumer=fake).run(stop=stop)
    assert fake.closed
