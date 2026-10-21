# services/api/tests/test_findings_api.py
from fastapi import FastAPI
from fastapi.testclient import TestClient

from packages.detection.models import Finding
from services.api.middleware.auth import Role, create_access_token
from services.api.routers import findings as findings_router

TENANT = "acmecorp"


def _finding(rule_id: str, nodes: list[str], severity: str, confidence: float) -> Finding:
    return Finding(tenant_id=TENANT, rule_id=rule_id, severity=severity, title=f"{rule_id} title",
                   description="d", affected_nodes=nodes, affected_node_names=nodes,
                   remediation_hint="fix", confidence_score=confidence)


FAKE_FINDINGS = [
    _finding("IAM-001", ["u1"], "HIGH", 0.9),
    _finding("IAM-001", ["u1"], "HIGH", 0.95),          # doublon : doit être écarté
    _finding("ATTACK-PATH-001-PARTIAL", ["u1", "r1", "d1"], "CRITICAL", 0.88),
    _finding("STORAGE-PUBLIC-001", ["b1"], "HIGH", 0.85),
    _finding("CIS-003", ["a1"], "MEDIUM", 0.8),
]


AUDIT_LOG: list = []


async def _fake_record(entry) -> None:
    AUDIT_LOG.append(entry)


def _app(monkeypatch) -> FastAPI:
    monkeypatch.setattr(findings_router, "_detect", lambda tenant_id: [
        f.model_copy(deep=True) for f in FAKE_FINDINGS])
    monkeypatch.setattr(findings_router, "_store", {})
    monkeypatch.setattr(findings_router.audit, "record", _fake_record)
    AUDIT_LOG.clear()
    app = FastAPI()
    app.include_router(findings_router.router)
    return app


def _auth(role: Role, tenant: str = TENANT) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token('alice', role, tenant)}"}


def _base(path: str = "") -> str:
    return f"/api/v1/tenants/{TENANT}/findings{path}"


def test_list_requires_authentication(monkeypatch):
    client = TestClient(_app(monkeypatch))
    assert client.get(_base("/")).status_code == 401


def test_list_is_deduplicated_and_sorted_by_severity(monkeypatch):
    client = TestClient(_app(monkeypatch))
    r = client.get(_base("/"), headers=_auth(Role.VIEWER))
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 4  # 5 entrées, 1 doublon écarté
    assert body[0]["severity"] == "CRITICAL"
    iam = [f for f in body if f["rule_id"] == "IAM-001"]
    assert len(iam) == 1 and iam[0]["confidence_score"] == 0.95


def test_filters_and_pagination(monkeypatch):
    client = TestClient(_app(monkeypatch))
    h = _auth(Role.VIEWER)
    assert [f["rule_id"] for f in client.get(_base("/?severity=high"), headers=h).json()] == \
        ["IAM-001", "STORAGE-PUBLIC-001"]
    assert len(client.get(_base("/?rule_id=CIS-003"), headers=h).json()) == 1
    assert len(client.get(_base("/?page=2&size=3"), headers=h).json()) == 1


def test_tenant_isolation_blocks_other_tenant(monkeypatch):
    client = TestClient(_app(monkeypatch))
    assert client.get(_base("/"), headers=_auth(Role.VIEWER, tenant="autre")).status_code == 403


def test_viewer_cannot_acknowledge(monkeypatch):
    client = TestClient(_app(monkeypatch))
    fid = client.get(_base("/"), headers=_auth(Role.VIEWER)).json()[0]["id"]
    assert client.post(_base(f"/{fid}/acknowledge"), headers=_auth(Role.VIEWER)).status_code == 403


def test_acknowledge_and_false_positive(monkeypatch):
    client = TestClient(_app(monkeypatch))
    op = _auth(Role.OPERATOR)
    fid = client.get(_base("/"), headers=op).json()[0]["id"]
    r = client.post(_base(f"/{fid}/acknowledge?justification=risque%20accepte"), headers=op)
    assert r.json()["status"] == "acknowledged"
    detail = client.get(_base(f"/{fid}"), headers=op).json()
    assert detail["status"] == "acknowledged"
    assert detail["metadata"]["justification"] == "risque accepte"
    client.post(_base(f"/{fid}/false-positive?reason=test"), headers=op)
    assert client.get(_base(f"/{fid}"), headers=op).json()["status"] == "false_positive"


def test_every_status_change_is_audited_before_applied(monkeypatch):
    client = TestClient(_app(monkeypatch))
    op = _auth(Role.OPERATOR)
    fid = client.get(_base("/"), headers=op).json()[0]["id"]
    client.post(_base(f"/{fid}/acknowledge?justification=ok"), headers=op)
    client.post(_base(f"/{fid}/resolve?justification=patché"), headers=op)
    assert [(e.action, e.old_status, e.new_status, e.actor) for e in AUDIT_LOG] == [
        ("acknowledged", "open", "acknowledged", "alice"),
        ("resolved", "acknowledged", "resolved", "alice"),
    ]
    assert AUDIT_LOG[0].justification == "ok"


def test_failed_audit_write_leaves_status_unchanged(monkeypatch):
    client = TestClient(_app(monkeypatch), raise_server_exceptions=False)
    op = _auth(Role.OPERATOR)
    fid = client.get(_base("/"), headers=op).json()[0]["id"]

    async def broken(entry) -> None:
        raise RuntimeError("PostgreSQL indisponible")

    monkeypatch.setattr(findings_router.audit, "record", broken)
    assert client.post(_base(f"/{fid}/false-positive"), headers=op).status_code == 500
    assert client.get(_base(f"/{fid}"), headers=op).json()["status"] == "open"


def test_same_status_transition_is_conflict(monkeypatch):
    client = TestClient(_app(monkeypatch))
    op = _auth(Role.OPERATOR)
    fid = client.get(_base("/"), headers=op).json()[0]["id"]
    client.post(_base(f"/{fid}/resolve"), headers=op)
    assert client.post(_base(f"/{fid}/resolve"), headers=op).status_code == 409


def test_refresh_keeps_id_and_status(monkeypatch):
    client = TestClient(_app(monkeypatch))
    op = _auth(Role.OPERATOR)
    before = client.get(_base("/"), headers=op).json()
    target = next(f for f in before if f["rule_id"] == "IAM-001")
    client.post(_base(f"/{target['id']}/acknowledge"), headers=op)
    client.post(_base("/refresh"), headers=op)
    after = client.get(_base("/"), headers=op).json()
    kept = next(f for f in after if f["rule_id"] == "IAM-001")
    assert kept["id"] == target["id"] and kept["status"] == "acknowledged"


def test_unknown_finding_returns_404(monkeypatch):
    client = TestClient(_app(monkeypatch))
    assert client.get(_base("/inexistant"), headers=_auth(Role.VIEWER)).status_code == 404


def test_stats_and_csv(monkeypatch):
    client = TestClient(_app(monkeypatch))
    h = _auth(Role.VIEWER)
    stats = client.get(_base("/stats"), headers=h).json()
    assert stats == {"total": 4, "by_severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1}, "open": 4}
    csv_resp = client.get(_base("/export/csv"), headers=h)
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert csv_resp.text.splitlines()[0].startswith("id,rule_id,severity")
    assert len(csv_resp.text.splitlines()) == 5  # en-tête + 4 findings
