# services/api/er_audit.py
"""
Décisions de validation humaine des paires ER (P2.6) — RÈGLE 4 : append-only, aucune suppression.

Chaque décision (merge | reject | flag) est une ligne de er_decisions, protégée par un trigger qui
refuse UPDATE, DELETE et TRUNCATE. Une paire peut recevoir plusieurs décisions (ex. flag puis merge) :
la DERNIÈRE fait foi, l'historique reste. Ces lignes alimentent le réentraînement du modèle Splink.
Une écriture qui échoue doit faire échouer l'action : pas de décision sans trace.
"""
import hashlib
from dataclasses import dataclass

from services.api.audit import get_pool

SCHEMA = """
CREATE TABLE IF NOT EXISTS er_decisions (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          TEXT             NOT NULL,
    pair_id            TEXT             NOT NULL,
    node_a_id          TEXT             NOT NULL,
    node_b_id          TEXT             NOT NULL,
    match_probability  DOUBLE PRECISION NOT NULL,
    decision           TEXT             NOT NULL CHECK (decision IN ('merge', 'reject', 'flag')),
    reviewer           TEXT             NOT NULL,
    note               TEXT,
    decided_at         TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION er_decisions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'er_decisions is append-only (RÈGLE 4)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS er_decisions_no_update_delete ON er_decisions;
CREATE TRIGGER er_decisions_no_update_delete
    BEFORE UPDATE OR DELETE ON er_decisions
    FOR EACH ROW EXECUTE FUNCTION er_decisions_append_only();

DROP TRIGGER IF EXISTS er_decisions_no_truncate ON er_decisions;
CREATE TRIGGER er_decisions_no_truncate
    BEFORE TRUNCATE ON er_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION er_decisions_append_only();

CREATE INDEX IF NOT EXISTS er_decisions_by_pair ON er_decisions (tenant_id, pair_id, decided_at);
"""

# Dernière décision par paire : c'est elle qui fait foi.
LATEST = """
SELECT DISTINCT ON (pair_id) pair_id, node_a_id, node_b_id, match_probability, decision,
       reviewer, note, decided_at
FROM er_decisions WHERE tenant_id = $1
ORDER BY pair_id, decided_at DESC, id DESC
"""


@dataclass(frozen=True)
class Decision:
    tenant_id: str
    pair_id: str
    node_a_id: str
    node_b_id: str
    match_probability: float
    decision: str
    reviewer: str
    note: str | None = None


def pair_id_for(node_a_id: str, node_b_id: str) -> str:
    """Identifiant stable et indépendant de l'ordre des deux nœuds."""
    a, b = sorted((node_a_id, node_b_id))
    return hashlib.sha1(f"{a}|{b}".encode()).hexdigest()[:16]


async def init_er_db() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


async def record(d: Decision) -> None:
    """Insère une décision. Lève une exception si l'insertion échoue."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO er_decisions (tenant_id, pair_id, node_a_id, node_b_id,
                                         match_probability, decision, reviewer, note)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            d.tenant_id, d.pair_id, d.node_a_id, d.node_b_id, d.match_probability,
            d.decision, d.reviewer, d.note,
        )


async def latest_decisions(tenant_id: str) -> dict[str, dict]:
    """pair_id -> dernière décision."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(LATEST, tenant_id)
    return {r["pair_id"]: dict(r) for r in rows}


async def stats(tenant_id: str) -> dict[str, int]:
    """Comptes sur la dernière décision de chaque paire ; total_decisions inclut l'historique."""
    latest = await latest_decisions(tenant_id)
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT count(*) FROM er_decisions WHERE tenant_id = $1",
                                    tenant_id)
    count = lambda kind: sum(1 for d in latest.values() if d["decision"] == kind)  # noqa: E731
    return {"total_reviewed": len(latest), "total_decisions": int(total),
            "merged": count("merge"), "rejected": count("reject"), "flagged": count("flag")}


async def merged_pairs(tenant_id: str) -> list[tuple[str, str]]:
    """Paires validées comme doublons (dernière décision = merge) : positifs du réentraînement."""
    latest = await latest_decisions(tenant_id)
    return [(d["node_a_id"], d["node_b_id"]) for d in latest.values() if d["decision"] == "merge"]
