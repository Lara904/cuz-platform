# services/api/tests/test_entity_resolution_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.api.middleware.auth import Role, create_access_token
from services.api.routers import entity_resolution as er_router

TENANT = "acmecorp"
URL = f"/api/v1/tenants/{TENANT}/entity-resolution/stats"


def _client(monkeypatch, stats: dict | None) -> TestClient:
    monkeypatch.setattr(er_router, "_stats", lambda t: stats)
    app = FastAPI()
    app.include_router(er_router.router)
    return TestClient(app)


def _auth(tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('auditor', Role.VIEWER, tenant)}"}


def test_stats_returned(monkeypatch):
    stats = {"tenant_id": TENANT, "total_nodes": 284, "auto_merge_pairs": 0,
             "pending_review_pairs": 0, "duplicate_rate_pct": 0.0,
             "duplicate_rate_basis": "estimated_from_model"}
    r = _client(monkeypatch, stats).get(URL, headers=_auth())
    assert r.status_code == 200 and r.json() == stats


def test_stats_409_when_model_not_trained(monkeypatch):
    assert _client(monkeypatch, None).get(URL, headers=_auth()).status_code == 409


def test_stats_requires_auth(monkeypatch):
    assert _client(monkeypatch, {}).get(URL).status_code in (401, 403)


def test_stats_refuses_other_tenant(monkeypatch):
    assert _client(monkeypatch, {}).get(URL, headers=_auth("other")).status_code == 403


# ── P2.6 : validation humaine des paires ─────────────────────────────────────

import pytest  # noqa: E402

from services.api import er_audit  # noqa: E402

BASE = f"/api/v1/tenants/{TENANT}/entity-resolution"


def _pair(pid: str, prob: float = 0.78) -> dict:
    return {"pair_id": pid, "match_probability": prob,
            "node_a": {"id": f"a-{pid}", "name": "srv-01", "node_type": "SERVER", "sources": ["servicenow"],
                       "attributes": {"ip_address": "10.0.0.1"}},
            "node_b": {"id": f"b-{pid}", "name": "srv-O1", "node_type": "SERVER", "sources": ["azure"],
                       "attributes": {}}}


class FakeAudit:
    """Remplace er_audit : ajout seul en mémoire, dernière décision par paire."""

    def __init__(self) -> None:
        self.rows: list[er_audit.Decision] = []
        self.fail = False

    async def record(self, d):
        if self.fail:
            raise RuntimeError("PostgreSQL indisponible")
        self.rows.append(d)

    async def latest_decisions(self, tenant_id):
        return {d.pair_id: {"decision": d.decision} for d in self.rows if d.tenant_id == tenant_id}

    async def stats(self, tenant_id):
        latest = await self.latest_decisions(tenant_id)
        n = lambda k: sum(1 for v in latest.values() if v["decision"] == k)  # noqa: E731
        return {"total_reviewed": len(latest), "total_decisions": len(self.rows),
                "merged": n("merge"), "rejected": n("reject"), "flagged": n("flag")}

    pair_id_for = staticmethod(er_audit.pair_id_for)
    Decision = er_audit.Decision


@pytest.fixture
def review(monkeypatch):
    fake = FakeAudit()
    monkeypatch.setattr(er_router, "er_audit", fake)
    monkeypatch.setattr(er_router, "_review_pairs", lambda t: [_pair("p1"), _pair("p2", 0.65)])
    app = FastAPI()
    app.include_router(er_router.router)
    return TestClient(app), fake


def _auth_role(role: Role, sub: str = "lara") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(sub, role, TENANT)}"}


def test_list_pending_pairs(review):
    client, _ = review
    body = client.get(f"{BASE}/pairs", headers=_auth()).json()
    assert body["total"] == 2 and body["pairs"][0]["pair_id"] == "p1"
    assert body["pairs"][0]["node_a"]["attributes"]["ip_address"] == "10.0.0.1"


def test_list_pairs_409_without_model(monkeypatch):
    monkeypatch.setattr(er_router, "_review_pairs", lambda t: None)
    app = FastAPI()
    app.include_router(er_router.router)
    assert TestClient(app).get(f"{BASE}/pairs", headers=_auth()).status_code == 409


def test_decide_merge_records_decision_with_token_identity(review):
    client, fake = review
    r = client.post(f"{BASE}/pairs/p1/decide", json={"decision": "merge", "note": "même CI"},
                    headers=_auth_role(Role.OPERATOR, "lara"))
    assert r.status_code == 200 and r.json()["graph_merge_applied"] is False
    assert [(d.pair_id, d.decision, d.reviewer) for d in fake.rows] == [("p1", "merge", "lara")]
    assert client.get(f"{BASE}/decisions/stats", headers=_auth()).json()["merged"] == 1
    # la paire décidée sort de la file d'attente
    assert client.get(f"{BASE}/pairs", headers=_auth()).json()["total"] == 1


def test_reviewer_from_body_is_ignored(review):
    client, fake = review
    client.post(f"{BASE}/pairs/p1/decide", json={"decision": "reject", "reviewer": "usurpateur"},
                headers=_auth_role(Role.OPERATOR, "lara"))
    assert fake.rows[0].reviewer == "lara"


def test_flag_keeps_pair_pending_and_marks_it(review):
    client, _ = review
    client.post(f"{BASE}/pairs/p1/decide", json={"decision": "flag"},
                headers=_auth_role(Role.OPERATOR))
    pairs = client.get(f"{BASE}/pairs", headers=_auth()).json()["pairs"]
    assert [(p["pair_id"], p["flagged"]) for p in pairs] == [("p1", True), ("p2", False)]


def test_decide_invalid_decision_is_rejected(review):
    client, _ = review
    r = client.post(f"{BASE}/pairs/p1/decide", json={"decision": "maybe"},
                    headers=_auth_role(Role.OPERATOR))
    assert r.status_code == 422


def test_decide_unknown_pair_404_and_already_decided_409(review):
    client, _ = review
    h = _auth_role(Role.OPERATOR)
    assert client.post(f"{BASE}/pairs/nope/decide", json={"decision": "merge"}, headers=h).status_code == 404
    client.post(f"{BASE}/pairs/p1/decide", json={"decision": "reject"}, headers=h)
    assert client.post(f"{BASE}/pairs/p1/decide", json={"decision": "merge"}, headers=h).status_code == 409


def test_decide_requires_operator_role(review):
    client, fake = review
    r = client.post(f"{BASE}/pairs/p1/decide", json={"decision": "merge"}, headers=_auth_role(Role.VIEWER))
    assert r.status_code == 403 and not fake.rows


def test_audit_failure_fails_the_action(review):
    client, fake = review
    fake.fail = True
    with pytest.raises(RuntimeError):  # pas de succès sans trace (règle 4)
        client.post(f"{BASE}/pairs/p1/decide", json={"decision": "merge"},
                    headers=_auth_role(Role.OPERATOR))
    assert not fake.rows


def test_pair_id_is_order_independent():
    assert er_audit.pair_id_for("x", "y") == er_audit.pair_id_for("y", "x")
    assert er_audit.pair_id_for("x", "y") != er_audit.pair_id_for("x", "z")
