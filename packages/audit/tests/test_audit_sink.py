# packages/audit/tests/test_audit_sink.py
"""Tests de PostgresAuditSink (P2.12) --- aucune connexion Postgres réelle, le pool est
remplacé par un FakePool monkeypatché sur get_pool(). Vérifie en particulier (DEC-007,
l'écart corrigé par rapport au guide P2.12) que record() est bien awaité jusqu'au bout
--- jamais un fire-and-forget qui pourrait perdre silencieusement un événement --- et
qu'une erreur d'écriture n'est jamais avalée."""

import json

import pytest

from packages.audit import audit_sink as audit_sink_module
from packages.audit.audit_sink import PostgresAuditSink

TENANT = "acmecorp"


class FakeConn:
    def __init__(self, fetch_result=None, raise_on_execute: Exception | None = None):
        self.executed: list[tuple] = []
        self._fetch_result = fetch_result or []
        self._raise_on_execute = raise_on_execute

    async def execute(self, query, *params):
        if self._raise_on_execute:
            raise self._raise_on_execute
        self.executed.append((query, params))

    async def fetch(self, query, *params):
        return self._fetch_result


class FakePool:
    def __init__(self, fetch_result=None, raise_on_execute: Exception | None = None):
        self.conn = FakeConn(fetch_result=fetch_result, raise_on_execute=raise_on_execute)

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def _patch_pool(monkeypatch, pool: FakePool) -> None:
    async def fake_get_pool(dsn: str = audit_sink_module.DATABASE_URL_DEFAULT):
        return pool

    monkeypatch.setattr(audit_sink_module, "get_pool", fake_get_pool)


def test_audit_sink_has_no_delete_or_update_method():
    """RÈGLE 4 étendue : aucune méthode de suppression/modification n'est exposée par le
    sink, au-delà de l'interdiction SQL côté trigger (cf. SCHEMA)."""
    sink = PostgresAuditSink(tenant_id=TENANT)
    assert not hasattr(sink, "delete")
    assert not hasattr(sink, "update")


@pytest.mark.asyncio
async def test_record_awaits_the_insert_before_returning(monkeypatch):
    """DEC-007 : record() n'est pas un fire-and-forget --- l'insertion est effectivement
    exécutée (et donc confirmée) avant que record() ne retourne."""
    pool = FakePool()
    _patch_pool(monkeypatch, pool)
    sink = PostgresAuditSink(tenant_id=TENANT, actor="IAMAgent")

    await sink.record(
        "jit_credential_acquired", "action-1", {"role": "cuz-agent-iam"}, finding_id="f-1"
    )

    assert len(pool.conn.executed) == 1
    query, params = pool.conn.executed[0]
    assert "INSERT INTO audit_events" in query
    tenant_id, action_id, event_type, actor, finding_id, payload_json = params
    assert (tenant_id, action_id, event_type, actor, finding_id) == (
        TENANT,
        "action-1",
        "jit_credential_acquired",
        "IAMAgent",
        "f-1",
    )
    assert json.loads(payload_json) == {"role": "cuz-agent-iam"}


@pytest.mark.asyncio
async def test_record_propagates_write_failure_instead_of_swallowing_it(monkeypatch):
    """DEC-007 : une écriture d'audit qui échoue doit faire échouer l'appelant --- jamais
    de perte silencieuse (même principe que services/api/audit.py)."""
    pool = FakePool(raise_on_execute=RuntimeError("db down"))
    _patch_pool(monkeypatch, pool)
    sink = PostgresAuditSink(tenant_id=TENANT)

    with pytest.raises(RuntimeError):
        await sink.record("jit_credential_acquired", "action-1", {})


@pytest.mark.asyncio
async def test_export_for_regulator_returns_ordered_events(monkeypatch):
    pool = FakePool(
        fetch_result=[
            {
                "id": "1",
                "action_id": "a1",
                "event_type": "remediation_executed",
                "actor": "NetworkAgent",
                "finding_id": "f1",
                "payload": {},
                "created_at": None,
            }
        ]
    )
    _patch_pool(monkeypatch, pool)
    sink = PostgresAuditSink(tenant_id=TENANT)

    events = await sink.export_for_regulator()
    assert len(events) == 1
    assert events[0]["event_type"] == "remediation_executed"
