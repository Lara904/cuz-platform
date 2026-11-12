# services/api/tests/test_findings_feed.py
"""Lien API <- cuz.findings.{tenant} (P2.8) : store réactif et flux Kafka."""

import logging
from typing import Any

import pytest
from confluent_kafka import KafkaError
from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.dedup import fingerprint
from packages.detection.models import Finding
from services.api.findings_feed import TOPIC_PATTERN, FindingsFeed, feed_enabled
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import findings as findings_router

TENANT = "acmecorp"
TOPIC = f"cuz.findings.{TENANT}"


def _finding(rule: str = "IAM-001", node: str = "u1", tenant: str = TENANT) -> Finding:
    return Finding(
        tenant_id=tenant,
        rule_id=rule,
        severity="HIGH",
        title=f"{rule} title",
        description="d",
        affected_nodes=[node],
        affected_node_names=[node],
        remediation_hint="fix",
        confidence_score=0.9,
    )


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setattr(findings_router, "_store", {})
    monkeypatch.setattr(findings_router, "_scan_buffers", {})
    detected: list[Finding] = []
    monkeypatch.setattr(
        findings_router, "_detect", lambda t: [f.model_copy(deep=True) for f in detected]
    )
    return detected


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(findings_router.router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('alice', Role.VIEWER, TENANT)}"}


def _list() -> list[dict[str, Any]]:
    r = _client().get(f"/api/v1/tenants/{TENANT}/findings/", headers=_auth())
    assert r.status_code == 200
    return r.json()


# ── store : ingest_reactive ─────────────────────────────────────────────────


def test_reactive_finding_is_visible_without_a_full_recompute(store):
    store.append(_finding("ATTACK-PATH-001-PARTIAL", "a"))
    assert len(_list()) == 1  # premier calcul complet : le store existe
    assert findings_router.ingest_reactive(_finding("IAM-001", "u1")) is True
    assert {f["rule_id"] for f in _list()} == {"ATTACK-PATH-001-PARTIAL", "IAM-001"}


def test_reactive_finding_for_unloaded_tenant_is_not_stored(store):
    """Sinon l'API ne montrerait QUE les findings réactifs et sauterait le calcul complet."""
    assert findings_router.ingest_reactive(_finding()) is False
    assert TENANT not in findings_router._store
    store.append(_finding("CIS-003", "x"))
    assert [f["rule_id"] for f in _list()] == ["CIS-003"]  # le calcul complet fait foi


def test_known_finding_keeps_its_status_and_id(store):
    store.append(_finding())
    original = _list()[0]
    stored = next(iter(findings_router._store[TENANT].values()))
    stored.status = "acknowledged"
    assert findings_router.ingest_reactive(_finding()) is False  # déjà connu
    again = _list()[0]
    assert again["id"] == original["id"] and again["status"] == "acknowledged"


def test_finding_arriving_during_a_full_scan_is_merged(monkeypatch, store):
    late = _finding("IAM-001", "late")

    def detect(tenant_id: str) -> list[Finding]:
        findings_router.ingest_reactive(late)  # publié pendant le calcul
        return [_finding("CIS-003", "x")]

    monkeypatch.setattr(findings_router, "_detect", detect)
    assert {f["rule_id"] for f in _list()} == {"CIS-003", "IAM-001"}


def test_late_finding_adopts_status_of_previous_store_on_refresh(monkeypatch, store):
    store.append(_finding("IAM-001", "u1"))
    first = _list()[0]
    next(iter(findings_router._store[TENANT].values())).status = "false_positive"

    def detect(tenant_id: str) -> list[Finding]:
        findings_router.ingest_reactive(_finding("IAM-001", "u1"))
        return []  # le calcul complet ne la voit plus

    monkeypatch.setattr(findings_router, "_detect", detect)
    findings_router._load(TENANT, refresh=True)
    kept = next(iter(findings_router._store[TENANT].values()))
    assert kept.id == first["id"] and kept.status == "false_positive"


def test_full_recompute_is_authoritative_and_drops_resolved_findings(store):
    store.append(_finding("CIS-003", "x"))
    _list()
    findings_router.ingest_reactive(_finding("IAM-001", "u1"))
    findings_router._load(TENANT, refresh=True)  # IAM-001 n'est plus produit par run_all
    assert {f["rule_id"] for f in _list()} == {"CIS-003"}


def test_failed_scan_leaves_no_buffer_behind(monkeypatch, store):
    def boom(tenant_id: str) -> list[Finding]:
        raise RuntimeError("neo4j down")

    monkeypatch.setattr(findings_router, "_detect", boom)
    with pytest.raises(RuntimeError):
        findings_router._load(TENANT)
    assert findings_router._scan_buffers == {}


def test_concurrent_scans_each_drop_only_their_own_buffer(store):
    a: dict = {}
    b: dict = {}  # deux tampons vides sont ==, la suppression doit se faire par identité
    findings_router._scan_buffers[TENANT] = [a, b]
    findings_router._drop_buffer(TENANT, a)
    assert findings_router._scan_buffers[TENANT][0] is b
    findings_router._drop_buffer(TENANT, b)
    assert TENANT not in findings_router._scan_buffers


def test_ingest_does_not_leak_across_tenants(store):
    store.append(_finding("CIS-003", "x"))
    _list()
    other = _finding("IAM-001", "u1", tenant="globex")
    assert findings_router.ingest_reactive(other) is False
    assert {f["rule_id"] for f in _list()} == {"CIS-003"}


# ── flux Kafka ──────────────────────────────────────────────────────────────


class Msg:
    def __init__(self, topic: str = TOPIC, value: bytes | None = b"", error: Any = None) -> None:
        self._topic, self._value, self._error = topic, value, error

    def topic(self) -> str:
        return self._topic

    def value(self) -> bytes | None:
        return self._value

    def error(self) -> Any:
        return self._error


class Err:
    def __init__(self, code: int) -> None:
        self._code = code

    def code(self) -> int:
        return self._code

    def __str__(self) -> str:
        return f"err{self._code}"


class FakeConsumer:
    """Sert les éléments dans l'ordre ; une Exception est levée ; à la fin, arrête le flux."""

    def __init__(self, items: list[Any]) -> None:
        self.items = list(items)
        self.subscribed: list[str] = []
        self.closed = False
        self.feed: FindingsFeed | None = None

    def subscribe(self, topics: list[str]) -> None:
        self.subscribed = topics

    def poll(self, timeout: float) -> Any:
        if not self.items:
            assert self.feed is not None
            self.feed._stop.set()
            return None
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


def _msg(finding: Finding, topic: str = TOPIC) -> Msg:
    return Msg(topic, finding.model_dump_json().encode())


def _feed(items: list[Any], on_finding=None, **kw: Any) -> tuple[FindingsFeed, list[Finding]]:
    received: list[Finding] = []

    def default(f: Finding) -> bool:
        received.append(f)
        return True

    consumer = FakeConsumer(items)
    feed = FindingsFeed(on_finding or default, consumer=consumer, **kw)
    consumer.feed = feed
    return feed, received


def test_valid_message_reaches_the_store_callback():
    feed, received = _feed([_msg(_finding())])
    feed.run()
    assert [f.rule_id for f in received] == ["IAM-001"]
    assert feed.stats["ingested"] == 1
    assert feed.consumer.subscribed == [TOPIC_PATTERN]
    assert feed.consumer.closed


def test_tenant_mismatch_between_topic_and_finding_is_rejected():
    feed, received = _feed([_msg(_finding(tenant="globex"), topic=TOPIC)])
    feed.run()
    assert received == [] and feed.stats["rejected"] == 1


def test_garbage_and_empty_messages_are_rejected_without_stopping_the_feed():
    feed, received = _feed([Msg(value=b"pas du json"), Msg(value=None), _msg(_finding())])
    feed.run()
    assert feed.stats["rejected"] == 2 and len(received) == 1


def test_handler_exception_does_not_stop_the_feed():
    calls: list[str] = []

    def flaky(f: Finding) -> bool:
        calls.append(f.rule_id)
        if f.rule_id == "BOOM":
            raise RuntimeError("x")
        return True

    feed, _ = _feed([_msg(_finding("BOOM")), _msg(_finding("IAM-001"))], on_finding=flaky)
    feed.run()
    assert calls == ["BOOM", "IAM-001"]
    assert feed.stats["errors"] == 1 and feed.stats["ingested"] == 1


def test_duplicates_are_counted_separately():
    feed, _ = _feed([_msg(_finding())], on_finding=lambda f: False)
    feed.run()
    assert feed.stats["duplicates"] == 1 and feed.stats["ingested"] == 0


def test_missing_topic_error_is_silent_and_other_errors_are_throttled(caplog):
    now = [0.0]
    unknown = Msg(error=Err(KafkaError.UNKNOWN_TOPIC_OR_PART))
    broker = Msg(error=Err(KafkaError._TRANSPORT))
    feed, _ = _feed([unknown, broker, broker, broker], clock=lambda: now[0])
    with caplog.at_level(logging.WARNING, logger="findings_feed"):
        feed.run()
    warnings = [r for r in caplog.records if "erreur Kafka" in r.message]
    assert (
        len(warnings) == 1
    )  # 3 erreurs broker en < 60 s : une seule trace, le « topic absent » aucune


def test_poll_exception_is_survived(caplog):
    feed, received = _feed([RuntimeError("socket"), _msg(_finding())])
    with caplog.at_level(logging.WARNING, logger="findings_feed"):
        feed.run()
    assert len(received) == 1


def test_feed_to_api_end_to_end(store):
    """Un message Kafka devient visible dans GET /findings sans recalcul complet."""
    store.append(_finding("CIS-003", "x"))
    assert len(_list()) == 1
    feed, _ = _feed([_msg(_finding("IAM-001", "u9"))], on_finding=findings_router.ingest_reactive)
    feed.run()
    assert {f["rule_id"] for f in _list()} == {"CIS-003", "IAM-001"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, True), ("true", True), ("false", False), ("0", False), ("OFF", False), ("1", True)],
)
def test_feed_enabled_flag(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("CUZ_FINDINGS_FEED", raising=False)
    else:
        monkeypatch.setenv("CUZ_FINDINGS_FEED", value)
    assert feed_enabled() is expected


def test_fingerprint_is_the_dedup_key():
    assert fingerprint(_finding()) == fingerprint(_finding())
    assert fingerprint(_finding(node="a")) != fingerprint(_finding(node="b"))
