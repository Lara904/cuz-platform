# services/api/tests/test_er_audit_db.py
"""Vérifie la RÈGLE 4 de er_decisions contre la vraie base PostgreSQL (skip si indisponible)."""
import asyncio

import asyncpg
import pytest

from services.api import audit, er_audit

TENANT = "acmecorp-er-audit-test"


def _run(coro):
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
            await er_audit.init_er_db()
        except (OSError, asyncpg.PostgresError) as e:
            pytest.skip(f"PostgreSQL indisponible : {e}")
    _run(setup())


def _decision(pair: str, decision: str) -> er_audit.Decision:
    return er_audit.Decision(tenant_id=TENANT, pair_id=pair, node_a_id="a", node_b_id="b",
                             match_probability=0.7, decision=decision, reviewer="lara")


def test_update_delete_truncate_are_refused():
    async def go():
        await er_audit.record(_decision("db-1", "flag"))
        pool = await audit.get_pool()
        async with pool.acquire() as conn:
            for sql in (f"UPDATE er_decisions SET decision='merge' WHERE tenant_id='{TENANT}'",
                        f"DELETE FROM er_decisions WHERE tenant_id='{TENANT}'",
                        "TRUNCATE er_decisions"):
                with pytest.raises(asyncpg.PostgresError, match="append-only"):
                    await conn.execute(sql)
    _run(go())


def test_invalid_decision_value_is_refused_by_the_database():
    async def go():
        with pytest.raises(asyncpg.CheckViolationError):
            await er_audit.record(_decision("db-2", "maybe"))
    _run(go())


def test_latest_decision_wins_and_history_is_kept():
    async def go():
        await er_audit.record(_decision("db-3", "flag"))
        await er_audit.record(_decision("db-3", "merge"))
        latest = await er_audit.latest_decisions(TENANT)
        assert latest["db-3"]["decision"] == "merge"
        stats = await er_audit.stats(TENANT)
        assert stats["total_decisions"] >= 2 and stats["merged"] >= 1
        assert ("a", "b") in await er_audit.merged_pairs(TENANT)
    _run(go())
