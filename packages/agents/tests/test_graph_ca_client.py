# packages/agents/tests/test_graph_ca_client.py
"""Tests du client Graph dédié à IAMAgent (DEC-006) --- HTTP entièrement mocké (httpx.
MockTransport), aucun appel réseau réel. Vérifie en particulier le garde-fou propre à cet
agent : relecture après écriture, refus si le scope réel divergerait de ce qui a été
demandé (Graph n'offrant pas de dry-run sur cet endpoint, contrairement à Kubernetes)."""

import httpx
import pytest

from packages.agents.graph_ca_client import (
    ConditionalAccessVerificationError,
    GraphConditionalAccessClient,
)

TENANT = "acme-tenant-id"


class FakeGraph:
    def __init__(
        self,
        users: list[dict] | None = None,
        policy_after_write: dict | None = None,
    ) -> None:
        self.users = users if users is not None else [{"id": "u-1", "displayName": "diana.dev"}]
        self.created_policies: list[dict] = []
        # Permet de simuler une relecture qui diverge de ce qui a été écrit (ex. policy
        # modifiée entre temps, ou bug Graph) --- None = la relecture reflète fidèlement
        # ce qui a été posté.
        self._policy_after_write_override = policy_after_write

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "fake-token", "expires_in": 3600})

        if request.url.path == "/v1.0/users":
            return httpx.Response(200, json={"value": self.users})

        if (
            request.url.path == "/v1.0/identity/conditionalAccess/policies"
            and request.method == "POST"
        ):
            import json

            body = json.loads(request.content)
            created = {**body, "id": f"ca-{len(self.created_policies) + 1}"}
            self.created_policies.append(created)
            return httpx.Response(201, json=created)

        if request.url.path.startswith("/v1.0/identity/conditionalAccess/policies/"):
            policy_id = request.url.path.rsplit("/", 1)[-1]
            if self._policy_after_write_override is not None:
                return httpx.Response(200, json=self._policy_after_write_override)
            created = next(p for p in self.created_policies if p["id"] == policy_id)
            return httpx.Response(200, json=created)

        raise AssertionError(f"appel Graph inattendu : {request.method} {request.url.path}")


def _client(graph: FakeGraph) -> GraphConditionalAccessClient:
    return GraphConditionalAccessClient(
        entra_tenant_id=TENANT,
        client_id="cid",
        client_secret="secret",
        transport=httpx.MockTransport(graph.handler),
    )


@pytest.mark.asyncio
async def test_find_user_id_by_display_name_unique_match():
    graph = FakeGraph(users=[{"id": "u-1", "displayName": "diana.dev"}])
    client = _client(graph)
    assert await client.find_user_id_by_display_name("diana.dev") == "u-1"


@pytest.mark.asyncio
async def test_find_user_id_by_display_name_no_match_returns_none():
    graph = FakeGraph(users=[])
    client = _client(graph)
    assert await client.find_user_id_by_display_name("ghost") is None


@pytest.mark.asyncio
async def test_find_user_id_by_display_name_ambiguous_returns_none():
    graph = FakeGraph(
        users=[
            {"id": "u-1", "displayName": "diana.dev"},
            {"id": "u-2", "displayName": "diana.dev"},
        ]
    )
    client = _client(graph)
    assert await client.find_user_id_by_display_name("diana.dev") is None


@pytest.mark.asyncio
async def test_create_mfa_policy_is_scoped_to_exactly_one_user():
    graph = FakeGraph()
    client = _client(graph)
    policy = await client.create_mfa_policy_for_user("u-1")

    assert policy["conditions"]["users"]["includeUsers"] == ["u-1"]
    assert policy["state"] == "enabled"
    assert "mfa" in policy["grantControls"]["builtInControls"]
    # Jamais "All users", jamais un groupe --- un seul utilisateur, explicitement.
    assert graph.created_policies[0]["conditions"]["users"]["includeUsers"] == ["u-1"]


@pytest.mark.asyncio
async def test_create_mfa_policy_never_reuses_or_edits_an_existing_policy():
    graph = FakeGraph()
    client = _client(graph)
    await client.create_mfa_policy_for_user("u-1")
    await client.create_mfa_policy_for_user("u-2")

    # Deux créations indépendantes --- jamais de mise à jour d'une policy existante.
    assert len(graph.created_policies) == 2
    assert graph.created_policies[0]["id"] != graph.created_policies[1]["id"]


@pytest.mark.asyncio
async def test_create_mfa_policy_refuses_if_post_write_scope_diverges():
    """Graph n'offre pas de dry-run ici --- la relecture après écriture doit détecter un
    scope divergent (ex. state redevenu "disabled", ou includeUsers élargi) et refuser,
    au lieu de faire confiance à la réponse du POST initial."""
    graph = FakeGraph(
        policy_after_write={
            "id": "ca-1",
            "state": "disabled",
            "conditions": {},
            "grantControls": {},
        }
    )
    client = _client(graph)

    with pytest.raises(ConditionalAccessVerificationError):
        await client.create_mfa_policy_for_user("u-1")


@pytest.mark.asyncio
async def test_create_mfa_policy_refuses_if_scope_widened_to_other_users():
    graph = FakeGraph(
        policy_after_write={
            "id": "ca-1",
            "state": "enabled",
            "conditions": {"users": {"includeUsers": ["u-1", "u-2"]}},
            "grantControls": {"builtInControls": ["mfa"]},
        }
    )
    client = _client(graph)

    with pytest.raises(ConditionalAccessVerificationError):
        await client.create_mfa_policy_for_user("u-1")
