# packages/connectors/gitea/tests/test_gitea.py
import os

import pytest

from packages.connectors.gitea.connector import GiteaConnector
from packages.connectors.gitea.mapper import GiteaMapper
from packages.core.models.enums import EdgeType, NodeType


@pytest.fixture
def connector():
    return GiteaConnector(
        tenant_id="acmecorp",
        base_url=os.getenv("GITEA_URL", "http://localhost:3000"),
        admin_token=os.getenv("GITEA_ADMIN_TOKEN", ""),
        org="acmecorp",
    )


@pytest.mark.asyncio
async def test_connection(connector):
    assert await connector.test_connection() is True


@pytest.mark.asyncio
async def test_pull_full_returns_4_repos(connector):
    events = await connector.pull_full()
    repos = [e for e in events if e.raw_data.get("object_type") == "repository"]
    assert len(repos) == 4, f"Attendu 4 repos, obtenu {len(repos)}"


@pytest.mark.asyncio
async def test_backend_repo_has_qs_dependency(connector):
    events = await connector.pull_full()
    backend = next((e for e in events if e.raw_data.get("name") == "backend"), None)
    assert backend is not None, "Repo 'backend' non trouvé"
    deps = backend.raw_data.get("dependencies", [])
    qs_dep = next((d for d in deps if d["name"] == "qs"), None)
    assert qs_dep is not None, "Dépendance qs non trouvée dans backend"
    assert qs_dep["version"] == "6.5.2"


def test_mapper_dependency_node_type():
    mapper = GiteaMapper("acmecorp")
    dep = {"name": "qs", "version": "6.5.2", "ecosystem": "npm"}
    node = mapper.map_dependency(dep)
    assert node.node_type == NodeType.VULNERABILITY
    assert node.attributes["package_name"] == "qs"
    assert node.attributes["version"] == "6.5.2"


def test_mapper_edge_type():
    mapper = GiteaMapper("acmecorp")
    repo = mapper.map_repo(
        {
            "repo_id": "1",
            "name": "backend",
            "full_name": "acmecorp/backend",
            "private": True,
            "default_branch": "main",
            "owner": "acmecorp",
        }
    )
    dep = mapper.map_dependency({"name": "qs", "version": "6.5.2", "ecosystem": "npm"})
    edge = mapper.map_repo_dependency_edge(repo, dep)
    assert edge.edge_type == EdgeType.DEPENDS_ON


# ── P2.7 : webhook signé et relecture d'un dépôt ────────────────────────────

import httpx  # noqa: E402


def _mock_connector(handler) -> tuple[GiteaConnector, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    conn = GiteaConnector("acmecorp", "http://gitea.test", "tok")
    real_client = httpx.AsyncClient
    httpx.AsyncClient = lambda **kw: real_client(transport=httpx.MockTransport(recording), **kw)  # type: ignore[assignment]
    return conn, seen


@pytest.fixture
def restore_httpx():
    real = httpx.AsyncClient
    yield
    httpx.AsyncClient = real  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_webhook_is_registered_with_secret(monkeypatch, restore_httpx):
    monkeypatch.setenv("GITEA_WEBHOOK_SECRET", "s3cret")
    conn, seen = _mock_connector(
        lambda r: (
            httpx.Response(200, json=[]) if r.method == "GET" else httpx.Response(201, json={})
        )
    )
    async with httpx.AsyncClient() as client:
        assert (
            await conn._register_webhook(client, "acmecorp", "backend", "http://cuz/hook") is True
        )
    post = next(r for r in seen if r.method == "POST")
    body = __import__("json").loads(post.content)
    assert body["config"]["secret"] == "s3cret" and "push" in body["events"]


@pytest.mark.asyncio
async def test_existing_webhook_is_patched_to_carry_the_secret(monkeypatch, restore_httpx):
    monkeypatch.setenv("GITEA_WEBHOOK_SECRET", "s3cret")
    hooks = [{"id": 7, "config": {"url": "http://cuz/hook"}}]
    conn, seen = _mock_connector(lambda r: httpx.Response(200, json=hooks))
    async with httpx.AsyncClient() as client:
        assert (
            await conn._register_webhook(client, "acmecorp", "backend", "http://cuz/hook") is True
        )
    patch = next(r for r in seen if r.method == "PATCH")
    assert patch.url.path.endswith("/hooks/7")
    assert __import__("json").loads(patch.content)["config"]["secret"] == "s3cret"


@pytest.mark.asyncio
async def test_pull_repo_returns_repository_event_or_none(restore_httpx):
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/api/v1/repos/acmecorp/backend":
            return httpx.Response(
                200,
                json={
                    "id": 1,
                    "name": "backend",
                    "full_name": "acmecorp/backend",
                    "owner": {"login": "acmecorp"},
                    "default_branch": "main",
                },
            )
        if r.url.path.endswith("/raw/package.json"):
            return httpx.Response(200, text='{"dependencies": {"qs": "6.5.2"}}')
        return httpx.Response(404)

    conn, _ = _mock_connector(handler)
    event = await conn.pull_repo("acmecorp", "backend")
    assert event is not None and event.raw_data["object_type"] == "repository"
    assert {"name": "qs", "version": "6.5.2", "ecosystem": "npm"} in event.raw_data["dependencies"]
    assert await conn.pull_repo("acmecorp", "absent") is None
