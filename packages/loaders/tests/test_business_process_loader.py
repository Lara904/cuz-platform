# packages/loaders/tests/test_business_process_loader.py
from packages.core.models.enums import EdgeType, NodeType
from packages.loaders.business_process_loader import BusinessProcessLoader

FIXTURE = "tests/fixtures/acmecorp_business_processes.csv"


def _resolver(mapping: dict[str, str | None]):
    return lambda ref: mapping.get(ref)


def test_csv_creates_one_business_process_node_per_row():
    nodes = BusinessProcessLoader("acmecorp").load_csv(FIXTURE)
    assert len(nodes) == 3
    assert all(n.node_type == NodeType.BUSINESS_PROCESS for n, _ in nodes)
    assert nodes[0][0].attributes == {"criticality_raw": "critical"}


def test_events_link_each_process_to_its_asset_by_supports():
    loader = BusinessProcessLoader("acmecorp")
    resolve = _resolver({"Acme-Payment-SaaS": "n-pay", "Acme-HR-SaaS": "n-hr", "billing-api": "n-bill"})
    events, unresolved = loader.build_events(FIXTURE, resolve)
    edges = [e.edge for e in events if e.edge is not None]
    assert unresolved == []
    assert len(edges) == 3
    assert all(e.edge_type == EdgeType.SUPPORTS for e in edges)
    assert {e.source_id for e in edges} == {"n-pay", "n-hr", "n-bill"}  # asset → processus
    assert all(e.target_id.startswith("manual:bp-") for e in edges)  # cible = processus


def test_unresolved_asset_is_reported_and_no_link_is_invented():
    loader = BusinessProcessLoader("acmecorp")
    events, unresolved = loader.build_events(FIXTURE, _resolver({"Acme-Payment-SaaS": "n-pay"}))
    assert len([e for e in events if e.edge is not None]) == 1
    assert len(unresolved) == 2


def test_node_ids_are_stable_across_loads():
    a = BusinessProcessLoader("acmecorp").load_csv(FIXTURE)
    b = BusinessProcessLoader("acmecorp").load_csv(FIXTURE)
    assert [n.id for n, _ in a] == [n.id for n, _ in b]
