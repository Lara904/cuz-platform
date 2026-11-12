# services/api/tests/test_webhooks_api.py
import hashlib
import hmac
import json
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.core.models.events import EventType, RawEvent
from services.api.routers import webhooks

SECRET = "s3cret"
URL = "/api/v1/webhooks/gitea"


class FakeConnector:
    def __init__(self, event: RawEvent | None = None, error: Exception | None = None) -> None:
        self.event, self.error, self.calls = event, error, []

    async def pull_repo(self, owner: str, name: str):
        self.calls.append((owner, name))
        if self.error:
            raise self.error
        return self.event


def _repo_event() -> RawEvent:
    return RawEvent(
        event_id="e1",
        tenant_id="acmecorp",
        source="gitea",
        event_type=EventType.NODE_CREATED,
        timestamp=datetime(2000, 1, 1, tzinfo=UTC),
        raw_data={"object_type": "repository", "repo_id": "1", "name": "backend"},
    )


def _payload(ref: str = "refs/heads/main") -> dict:
    return {
        "ref": ref,
        "repository": {
            "id": 1,
            "name": "backend",
            "default_branch": "main",
            "owner": {"login": "acmecorp"},
        },
    }


def _sign(body: bytes, secret: str = SECRET) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setenv("GITEA_WEBHOOK_SECRET", SECRET)
    published: list[RawEvent] = []
    connector = FakeConnector(_repo_event())
    monkeypatch.setattr(webhooks, "_connector", lambda tenant: connector)
    monkeypatch.setattr(webhooks, "_publish", published.append)
    app = FastAPI()
    app.include_router(webhooks.router)
    return TestClient(app), published, connector


def _post(client, payload, *, event="push", signature=None, secret=SECRET, headers=None):
    body = json.dumps(payload).encode()
    h = {
        "X-Gitea-Event": event,
        "Content-Type": "application/json",
        "X-Gitea-Signature": _sign(body, secret) if signature is None else signature,
        **(headers or {}),
    }
    return client.post(URL, content=body, headers=h)


def test_signed_push_on_default_branch_is_published(hook):
    client, published, connector = hook
    r = _post(client, _payload())
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert connector.calls == [("acmecorp", "backend")]
    assert len(published) == 1 and published[0].raw_data["object_type"] == "repository"


def test_event_timestamp_is_webhook_reception_time(hook):
    client, published, _ = hook
    before = datetime.now(UTC)
    _post(client, _payload())
    assert before <= published[0].timestamp <= datetime.now(UTC)  # origine de la latence mesurée


def test_fails_closed_without_secret(hook, monkeypatch):
    client, published, _ = hook
    monkeypatch.delenv("GITEA_WEBHOOK_SECRET")
    assert _post(client, _payload(), signature="n-importe-quoi").status_code == 503
    assert not published  # jamais d'accepté « par défaut » en dev


def test_bad_or_missing_signature_is_rejected(hook):
    client, published, _ = hook
    assert _post(client, _payload(), signature="0" * 64).status_code == 401
    assert _post(client, _payload(), secret="autre-secret").status_code == 401
    assert _post(client, _payload(), signature="").status_code == 401
    assert not published


def test_hub_signature_header_is_accepted(hook):
    client, published, _ = hook
    body = json.dumps(_payload()).encode()
    r = client.post(
        URL,
        content=body,
        headers={
            "X-Gitea-Event": "push",
            "X-Gitea-Signature": "",
            "X-Hub-Signature-256": "sha256=" + _sign(body),
        },
    )
    assert r.status_code == 200 and len(published) == 1


def test_non_push_or_other_branch_is_ignored(hook):
    client, published, connector = hook
    assert _post(client, _payload(), event="create").json()["status"] == "ignored"
    assert _post(client, _payload("refs/heads/feature-x")).json()["status"] == "ignored"
    assert not published and not connector.calls


def test_malformed_payload_is_400(hook):
    client, published, _ = hook
    assert _post(client, {"ref": "refs/heads/main"}).status_code == 400
    assert not published


def test_oversized_payload_is_413(hook, monkeypatch):
    client, published, _ = hook
    monkeypatch.setattr(webhooks, "MAX_BODY_BYTES", 10)
    assert _post(client, _payload()).status_code == 413
    assert not published


def test_gitea_unreachable_is_502_and_nothing_published(hook, monkeypatch):
    client, published, _ = hook
    monkeypatch.setattr(
        webhooks, "_connector", lambda tenant: FakeConnector(error=httpx.ConnectError("down"))
    )
    assert _post(client, _payload()).status_code == 502
    assert not published


def test_unknown_repository_is_ignored(hook, monkeypatch):
    client, published, _ = hook
    monkeypatch.setattr(webhooks, "_connector", lambda tenant: FakeConnector(None))
    assert _post(client, _payload()).json()["status"] == "ignored"
    assert not published
