# packages/connectors/kubernetes/tests/test_correlate.py
from packages.connectors.kubernetes.correlate import GraphNode, _repo_segment, correlate
from packages.core.models.enums import EdgeType

T = "acmecorp"


def test_repo_segment_from_image_ref():
    assert _repo_segment("acmecorp/backend:latest") == "backend"
    assert _repo_segment("ubuntu:20.04") == "ubuntu"
    assert _repo_segment("registry.local/team/backend@sha256:abc") == "backend"


def test_affects_when_image_names_the_declaring_repo():
    vuln = GraphNode("v-qs", "qs@6.5.2", "VULNERABILITY", {})
    repo = GraphNode("r-backend", "backend", "REPOSITORY", {}, ("v-qs",))
    pod = GraphNode("p-legacy", "legacy-job", "CONTAINER", {"images": ["acmecorp/backend:latest"]})
    edges = correlate([pod], [repo], {"v-qs": vuln}, [], T)
    assert [(e.edge_type, e.source_id, e.target_id) for e in edges] == [
        (EdgeType.AFFECTS, "v-qs", "p-legacy")]


def test_no_affects_for_unrelated_image():
    vuln = GraphNode("v-qs", "qs@6.5.2", "VULNERABILITY", {})
    repo = GraphNode("r-backend", "backend", "REPOSITORY", {}, ("v-qs",))
    pod = GraphNode("p", "legacy-job", "CONTAINER", {"images": ["ubuntu:20.04"]})
    assert correlate([pod], [repo], {"v-qs": vuln}, [], T) == []


def test_exposes_only_for_publicly_exposed_pods():
    bucket = GraphNode("s-public", "acmecorp-public", "STORAGE", {})
    exposed = GraphNode("p-exp", "legacy-job", "CONTAINER", {"is_public_exposed": True})
    hidden = GraphNode("p-hid", "other", "CONTAINER", {"is_public_exposed": False})
    edges = correlate([exposed, hidden], [], {}, [bucket], T)
    assert [(e.edge_type, e.source_id, e.target_id) for e in edges] == [
        (EdgeType.EXPOSES, "p-exp", "s-public")]
