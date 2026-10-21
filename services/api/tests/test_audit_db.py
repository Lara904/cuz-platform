# services/api/tests/test_audit_db.py
"""Vérifie la RÈGLE 4 contre la vraie base PostgreSQL (skip si indisponible)."""
import asyncio
import uuid
from datetime import UTC, datetime

import asyncpg
import pytest

from services.api import audit

TENANT = "acmecorp-audit-test"


def _run(coro):
    """Chaque appel a sa propre boucle : on réinitialise le pool et on le ferme ensuite."""
    async def wrapper():
        audit._pool = None
        try:
            return await coro
        finally:
            if audit._pool is not None:
                await audit._pool.close()
                audit._pool = None
    return asyncio.run(wrapper())


@pytest.fixture(scope="module", autouse=True)
def _schema():
    async def setup():
        try:
            await audit.init_audit_db()
        except (OSError, asyncpg.PostgresError) as e:
            pytest.skip(f"PostgreSQL indisponible : {e}")
    _run(setup())
    yield


def _entry(finding_id: str = "f-audit-1") -> audit.AuditEntry:
    return audit.AuditEntry(tenant_id=TENANT, finding_id=finding_id, rule_id="IAM-001",
                            action="acknowledged", old_status="open",
                            new_status="acknowledged", actor="alice",
                            justification="test", expiry=datetime.now(UTC))


def test_record_and_read_back():
    # Table append-only : identifiant unique par exécution, pas de nettoyage possible
    fid = f"f-read-{uuid.uuid4()}"

    async def go():
        await audit.record(_entry(fid))
        return await audit.history(TENANT, fid)
    rows = _run(go())
    assert len(rows) == 1
    assert rows[0]["new_status"] == "acknowledged" and rows[0]["actor"] == "alice"


def test_update_is_refused():
    async def go():
        await audit.record(_entry("f-no-update"))
        pool = await audit.get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE finding_audit SET actor = 'mallory' WHERE finding_id = 'f-no-update'")
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        _run(go())


def test_delete_is_refused():
    async def go():
        await audit.record(_entry("f-no-delete"))
        pool = await audit.get_pool()
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM finding_audit WHERE finding_id = 'f-no-delete'")
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        _run(go())


def test_truncate_is_refused():
    async def go():
        pool = await audit.get_pool()
        async with pool.acquire() as conn:
            await conn.execute("TRUNCATE finding_audit")
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        _run(go())
