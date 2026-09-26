# packages/connectors/gitea/tests/test_gitea.py
import pytest
import os
from packages.connectors.gitea.connector import GiteaConnector
from packages.connectors.gitea.mapper import GiteaMapper
from packages.core.models.enums import NodeType, EdgeType

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
    backend = next(
        (e for e in events if e.raw_data.get("name") == "backend"), None
    )
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
    from packages.core.models.node import CuzNode
    from packages.core.models.enums import NodeType
    repo = mapper.map_repo({"repo_id": "1", "name": "backend",
                            "full_name": "acmecorp/backend",
                            "private": True, "default_branch": "main",
                            "owner": "acmecorp"})
    dep = mapper.map_dependency({"name": "qs", "version": "6.5.2", "ecosystem": "npm"})
    edge = mapper.map_repo_dependency_edge(repo, dep)
    assert edge.edge_type == EdgeType.DEPENDS_ON