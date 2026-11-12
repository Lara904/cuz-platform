# packages/detection/tests/test_opa_policies.py
"""Chargement robuste des policies OPA : un OPA sans policy ne doit JAMAIS ressembler à « zéro finding »."""

import json
import logging
from typing import Any

import httpx
import pytest

from packages.detection import opa_client
from packages.detection.models import Finding
from packages.detection.opa_client import (
    OPAClient,
    OPAError,
    OPAPolicyError,
    OPAUnavailableError,
)

TENANT = "acmecorp"
EXPECTED = OPAClient.expected_policies()


def _package_of(rego: str) -> str:
    line = next(line for line in rego.splitlines() if line.startswith("package "))
    return "cuz/" + line.split()[1].split(".")[1]


PACKAGE_TO_POLICY = {_package_of(text): pid for pid, text in EXPECTED.items()}


class FakeOPA:
    """Imite le comportement RÉEL d'OPA observé : un package dont la policy n'est pas chargée répond
    HTTP 200 avec `{}` (aucun champ `result`) ; une policy chargée sans violation répond
    `{"result": {}}` ; GET /v1/policies renvoie le texte exact poussé ; un PUT invalide renvoie 400."""

    def __init__(self, policies: dict[str, str] | None = None) -> None:
        self.policies = dict(policies or {})
        self.requests: list[tuple[str, str]] = []
        self.reject: set[str] = set()  # policies que le PUT refuse (400)
        self.down = False
        self.fail_after: int | None = None  # nombre de POST /v1/data avant coupure réseau
        self.http_500_packages: set[str] = set()
        self.garbage_packages: set[str] = set()
        self.undefined_packages: set[str] = set()  # package indéfini même policy chargée
        self._posts = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        path = request.url.path
        self.requests.append((request.method, path))
        if request.method == "GET" and path == "/v1/policies":
            return httpx.Response(
                200, json={"result": [{"id": i, "raw": t} for i, t in self.policies.items()]}
            )
        if request.method == "PUT" and path.startswith("/v1/policies/"):
            pid = path.rsplit("/", 1)[1]
            if pid in self.reject:
                return httpx.Response(
                    400, json={"code": "invalid_parameter", "message": f"compile error in {pid}"}
                )
            self.policies[pid] = request.content.decode()
            return httpx.Response(200, json={})
        package = path[len("/v1/data/") : -len("/deny")]
        self._posts += 1
        if self.fail_after is not None and self._posts > self.fail_after:
            raise httpx.ConnectError("coupure", request=request)
        if package in self.http_500_packages:
            return httpx.Response(500, text="boom")
        if package in self.garbage_packages:
            return httpx.Response(200, text="<html>pas du json</html>")
        loaded = PACKAGE_TO_POLICY.get(package) in self.policies
        if not loaded or package in self.undefined_packages:
            return httpx.Response(200, json={})  # ← le silence : HTTP 200, pas de "result"
        node = json.loads(request.content)["input"]["node"]
        deny: dict[str, bool] = {}
        if (
            package == "cuz/iam"
            and node["node_type"] == "USER"
            and node["attributes"].get("has_mfa") is False
        ):
            obj = {
                "rule_id": "IAM-OPA-001", "severity": "HIGH", "title": "t", "description": "d",
                "node_id": node["id"], "node_name": node["name"], "remediation_hint": "h",
            }  # fmt: skip
            deny[json.dumps(obj, sort_keys=True)] = True
        return httpx.Response(200, json={"result": deny})

    def puts(self) -> list[str]:
        return [p.rsplit("/", 1)[1] for m, p in self.requests if m == "PUT"]

    def posts(self) -> int:
        return sum(1 for m, p in self.requests if m == "POST")


def _client(fake: FakeOPA) -> OPAClient:
    return OPAClient(base_url="http://opa.interne:8181", transport=fake.transport())


def _user(i: int = 1, mfa: bool = False) -> dict[str, Any]:
    return {
        "id": f"u{i}",
        "tenant_id": TENANT,
        "name": f"user{i}",
        "node_type": "USER",
        "attributes": {"has_mfa": mfa, "account_enabled": True},
        "tags": {},
        "owner": None,
    }


# ── le fake est fidèle : l'OPA vide produit bien le silence ─────────────────


def test_fake_reproduces_the_silent_empty_answer_of_an_opa_without_policies():
    fake = FakeOPA()
    r = httpx.Client(transport=fake.transport()).post(
        "http://opa/v1/data/cuz/iam/deny", json={"input": {"node": _user()}}
    )
    assert r.status_code == 200 and r.json() == {}  # pas d'erreur, pas de "result"


# ── auto-réparation ─────────────────────────────────────────────────────────


def test_opa_without_any_policy_is_healed_and_findings_are_returned(caplog):
    """LE scénario : conteneur OPA redémarré, aucune policy. Avant : 0 finding, 0 erreur."""
    fake = FakeOPA()
    with caplog.at_level(logging.WARNING, logger="packages.detection.opa_client"):
        findings = _client(fake).evaluate_nodes([_user(1), _user(2, mfa=True)])
    assert [f.rule_id for f in findings] == ["IAM-OPA-001"]
    assert set(fake.policies) == set(EXPECTED)
    assert any("rechargées" in r.message for r in caplog.records)  # la réparation est tracée


def test_ensure_policies_loads_every_missing_policy():
    fake = FakeOPA()
    assert sorted(_client(fake).ensure_policies()) == sorted(EXPECTED)
    assert fake.policies == EXPECTED


def test_ensure_policies_is_idempotent_and_does_not_rewrite_up_to_date_policies():
    fake = FakeOPA(EXPECTED)
    assert _client(fake).ensure_policies() == []
    assert fake.puts() == []


def test_stale_policy_is_reloaded_alone():
    stale = dict(EXPECTED)
    stale["human_no_mfa"] = "package cuz.iam\n# version périmée"
    fake = FakeOPA(stale)
    assert _client(fake).ensure_policies() == ["human_no_mfa"]
    assert fake.policies["human_no_mfa"] == EXPECTED["human_no_mfa"]


def test_unknown_extra_policy_in_opa_is_left_alone():
    fake = FakeOPA({**EXPECTED, "autre_equipe": "package autre"})
    assert _client(fake).ensure_policies() == []
    assert "autre_equipe" in fake.policies


def test_policies_lost_between_two_evaluations_are_healed_again():
    fake = FakeOPA()
    client = _client(fake)
    assert len(client.evaluate_nodes([_user()])) == 1
    fake.policies.clear()  # redémarrage d'OPA entre deux calculs
    assert len(client.evaluate_nodes([_user()])) == 1


# ── jamais de « zéro finding » pour cause d'échec ───────────────────────────


def test_rejected_policy_raises_with_the_reason_and_evaluates_nothing():
    fake = FakeOPA()
    fake.reject = {"human_no_mfa"}
    with pytest.raises(OPAPolicyError, match=r"human_no_mfa.*400|400.*human_no_mfa|compile error"):
        _client(fake).evaluate_nodes([_user()])
    assert fake.posts() == 0


def test_opa_down_raises_and_fails_fast():
    fake = FakeOPA()
    fake.down = True
    with pytest.raises(OPAUnavailableError):
        _client(fake).evaluate_nodes([_user(i) for i in range(50)])
    assert (
        fake.requests == []
    )  # une seule tentative (rien n'est loggé quand c'est down), pas 250 timeouts


def test_ensure_policies_raises_when_opa_is_down():
    fake = FakeOPA()
    fake.down = True
    with pytest.raises(OPAUnavailableError, match="injoignable"):
        _client(fake).ensure_policies()


def test_network_cut_mid_evaluation_aborts_but_keeps_findings_already_found():
    fake = FakeOPA(EXPECTED)
    fake.fail_after = (
        6  # 5 packages du nœud 1, puis cuz/iam du nœud 2 (trouve son finding), puis coupure
    )
    with pytest.raises(OPAUnavailableError) as exc:
        _client(fake).evaluate_nodes([_user(1), _user(2), _user(3)])
    assert [f.affected_node_names for f in exc.value.partial_findings] == [["user1"], ["user2"]]
    assert fake.posts() == 7  # abandon à la première coupure, pas 15 requêtes


def test_http_errors_on_a_package_do_not_stop_the_others_but_are_reported():
    fake = FakeOPA(EXPECTED)
    fake.http_500_packages = {"cuz/tls"}
    with pytest.raises(OPAUnavailableError, match="2 requête") as exc:
        _client(fake).evaluate_nodes([_user(1), _user(2)])
    assert len(exc.value.partial_findings) == 2  # IAM-OPA-001 trouvé pour les deux nœuds quand même


def test_undefined_package_after_ensure_raises_a_policy_error():
    """Package renommé ou policy qui ne définit plus `deny` : réponse `{}`, c'est une erreur."""
    fake = FakeOPA(EXPECTED)
    fake.undefined_packages = {"cuz/network"}
    with pytest.raises(OPAPolicyError, match="cuz/network"):
        _client(fake).evaluate_nodes([_user()])


def test_unreadable_response_is_reported():
    fake = FakeOPA(EXPECTED)
    fake.garbage_packages = {"cuz/iam"}
    with pytest.raises(OPAUnavailableError, match="illisible"):
        _client(fake).evaluate_nodes([_user()])


def test_evaluated_with_no_violation_is_not_an_error():
    """`{"result": {}}` = policy évaluée, rien à signaler : distinct de `{}` (policy absente)."""
    fake = FakeOPA(EXPECTED)
    assert _client(fake).evaluate_nodes([_user(mfa=True)]) == []


def test_no_policy_files_in_the_repo_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(opa_client, "POLICY_DIR", tmp_path)
    with pytest.raises(OPAPolicyError, match="aucune policy"):
        _client(FakeOPA()).ensure_policies()


def test_public_summaries_do_not_leak_internal_details():
    """`summary` part dans l'API : ni URL interne, ni corps de réponse."""
    fake = FakeOPA()
    fake.down = True
    with pytest.raises(OPAError) as exc:
        _client(fake).evaluate_nodes([_user()])
    assert "opa.interne" in str(exc.value)  # le détail est dans l'exception, pour les journaux
    assert "opa.interne" not in exc.value.summary and "8181" not in exc.value.summary


def test_partial_findings_default_to_an_empty_list():
    assert OPAError("x").partial_findings == []
    assert all(isinstance(f, Finding) for f in OPAError("x", []).partial_findings)
