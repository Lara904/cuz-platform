# packages/entity-resolution/tests/test_entity_resolution.py
import pytest
from datetime import datetime, timezone
from packages.core.models.node import CuzNode
from packages.core.models.enums import NodeType, EdgeType
from packages.entity_resolution.resolver import DeterministicResolver
from packages.entity_resolution.merger import NodeMerger
from packages.entity_resolution.owner_linker import OwnerLinker

def make_node(name: str, source: str, ext_id: str, tenant: str = "acmecorp") -> CuzNode:
    return CuzNode(
        tenant_id=tenant,
        node_type=NodeType.SERVER,
        name=name,
        external_id=ext_id,
        external_ids={source: ext_id},
        confidence_score=0.8,
        freshness_score=0.9,
        sources=[source],
        last_seen=datetime.now(timezone.utc),
    )

def test_resolver_no_duplicate_different_ids():
    r = DeterministicResolver()
    n1 = make_node("srv-01", "servicenow", "sys_id_001")
    n2 = make_node("srv-02", "servicenow", "sys_id_002")
    r.register(n1)
    existing_id, is_dup = r.resolve(n2)
    assert not is_dup

def test_resolver_detects_duplicate_same_id():
    r = DeterministicResolver()
    n1 = make_node("srv-01", "servicenow", "sys_id_001")
    r.register(n1)
    n2 = make_node("srv-01-updated", "servicenow", "sys_id_001")
    existing_id, is_dup = r.resolve(n2)
    assert is_dup
    assert existing_id == n1.id

def test_merger_merges_multi_source():
    r = DeterministicResolver()
    m = NodeMerger(r)
    n1 = make_node("srv-01", "servicenow", "sys_id_001")
    n2 = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.SERVER,
        name="srv-01",
        external_id="sys_id_001",
        external_ids={"servicenow": "sys_id_001", "entra_id": "entra_001"},
        confidence_score=0.75,
        freshness_score=0.85,
        sources=["entra_id"],
        last_seen=datetime.now(timezone.utc),
    )
    merged1 = m.merge_or_create(n1)
    merged2 = m.merge_or_create(n2)
    assert merged2.id == merged1.id
    assert "entra_id" in merged2.sources
    assert "servicenow" in merged2.sources

def test_merger_confidence_increases_with_sources():
    r = DeterministicResolver()
    m = NodeMerger(r)
    n1 = make_node("bucket-x", "minio", "bucket-x")
    n2 = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.STORAGE,
        name="bucket-x",
        external_id="bucket-x",
        external_ids={"minio": "bucket-x", "gitea": "bucket-x"},
        confidence_score=0.9,
        freshness_score=0.9,
        sources=["gitea"],
        last_seen=datetime.now(timezone.utc),
    )
    m.merge_or_create(n1)
    merged = m.merge_or_create(n2)
    assert merged.confidence_score >= 0.8

def test_owner_linker_resolves_known_convention():
    linker = OwnerLinker()
    user = CuzNode(tenant_id="acmecorp", node_type=NodeType.USER, name="Djana Dev",
                    external_id="uid-001", confidence_score=0.9, freshness_score=0.9,
                    sources=["entra_id"], last_seen=datetime.now(timezone.utc),
                    attributes={"upn": "djana.dev@acmecorp.onmicrosoft.com"})
    repo = CuzNode(tenant_id="acmecorp", node_type=NodeType.REPOSITORY, name="backend",
                    external_id="42", confidence_score=0.9, freshness_score=0.9,
                    sources=["gitea"], last_seen=datetime.now(timezone.utc),
                    attributes={"owner": "djana.dev"})
    linker.register_user(user)
    edge = linker.resolve_owns_edge(repo)
    assert edge is not None
    assert edge.edge_type == EdgeType.OWNS

def test_owner_linker_returns_none_when_owner_unknown():
    linker = OwnerLinker()
    repo = CuzNode(tenant_id="acmecorp", node_type=NodeType.REPOSITORY, name="orphan-repo",
                    external_id="99", confidence_score=0.9, freshness_score=0.9,
                    sources=["gitea"], last_seen=datetime.now(timezone.utc),
                    attributes={"owner": "unknown-user"})
    assert linker.resolve_owns_edge(repo) is None

def test_merged_node_recognized_by_each_strong_key():
    """Fusion servicenow + entra_id : un 3e nœud porteur de l'entra_id seul
    doit être reconnu comme doublon (l'index couvre toutes les clés fortes)."""
    r = DeterministicResolver()
    m = NodeMerger(r)
    m.merge_or_create(make_node("srv-01", "servicenow", "sys_id_001"))
    n2 = CuzNode(
        tenant_id="acmecorp", node_type=NodeType.SERVER, name="srv-01",
        external_id="sys_id_001",
        external_ids={"servicenow": "sys_id_001", "entra_id": "entra_001"},
        confidence_score=0.75, freshness_score=0.85, sources=["entra_id"],
        last_seen=datetime.now(timezone.utc),
    )
    merged_id = m.merge_or_create(n2).id
    n3 = make_node("srv-01-entra", "entra_id", "entra_001")
    assert m.merge_or_create(n3).id == merged_id


def test_no_merge_across_tenants():
    """Même identifiant fort dans deux tenants → deux nœuds distincts."""
    r = DeterministicResolver()
    m = NodeMerger(r)
    a = m.merge_or_create(make_node("srv-01", "servicenow", "sys_id_001", tenant="tenant_a"))
    b = m.merge_or_create(make_node("srv-01", "servicenow", "sys_id_001", tenant="tenant_b"))
    assert a.id != b.id


def test_owner_linker_does_not_cross_tenants():
    """Un USER du tenant A ne doit pas être lié à un repo du tenant B."""
    linker = OwnerLinker()
    user = CuzNode(tenant_id="tenant_a", node_type=NodeType.USER, name="Djana Dev",
                   external_id="uid-001", confidence_score=0.9, freshness_score=0.9,
                   sources=["entra_id"], last_seen=datetime.now(timezone.utc),
                   attributes={"upn": "djana.dev@a.onmicrosoft.com"})
    repo_b = CuzNode(tenant_id="tenant_b", node_type=NodeType.REPOSITORY, name="backend",
                     external_id="42", confidence_score=0.9, freshness_score=0.9,
                     sources=["gitea"], last_seen=datetime.now(timezone.utc),
                     attributes={"owner": "djana.dev"})
    linker.register_user(user)
    assert linker.resolve_owns_edge(repo_b) is None


def test_owner_edge_carries_repo_tenant():
    linker = OwnerLinker()
    user = CuzNode(tenant_id="tenant_b", node_type=NodeType.USER, name="Djana Dev",
                   external_id="uid-001", confidence_score=0.9, freshness_score=0.9,
                   sources=["entra_id"], last_seen=datetime.now(timezone.utc),
                   attributes={"upn": "djana.dev@b.onmicrosoft.com"})
    repo = CuzNode(tenant_id="tenant_b", node_type=NodeType.REPOSITORY, name="backend",
                   external_id="42", confidence_score=0.9, freshness_score=0.9,
                   sources=["gitea"], last_seen=datetime.now(timezone.utc),
                   attributes={"owner": "djana.dev"})
    linker.register_user(user)
    edge = linker.resolve_owns_edge(repo)
    assert edge is not None and edge.tenant_id == "tenant_b"


def test_owner_mapping_takes_precedence_over_gitea_org_owner():
    """owner Gitea = organisation (acmecorp) : le mapping explicite prime."""
    linker = OwnerLinker(owner_mapping={"acmecorp/backend": "djana.dev"})
    user = CuzNode(tenant_id="acmecorp", node_type=NodeType.USER, name="djanaD",
                   external_id="uid-001", confidence_score=0.9, freshness_score=0.9,
                   sources=["entra_id"], last_seen=datetime.now(timezone.utc),
                   attributes={"upn": "djana.dev@acmecorp.onmicrosoft.com"})
    repo = CuzNode(tenant_id="acmecorp", node_type=NodeType.REPOSITORY, name="backend",
                   external_id="1", confidence_score=0.9, freshness_score=0.9,
                   sources=["gitea"], last_seen=datetime.now(timezone.utc),
                   attributes={"full_name": "acmecorp/backend", "owner": "acmecorp"})
    linker.register_user(user)
    assert linker.resolve_owns_edge(repo) is not None
    other = repo.model_copy(update={"attributes": {"full_name": "acmecorp/infra", "owner": "acmecorp"}})
    assert linker.resolve_owns_edge(other) is None
