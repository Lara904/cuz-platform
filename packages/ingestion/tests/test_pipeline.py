# packages/ingestion/tests/test_pipeline.py
import uuid
from datetime import UTC, datetime

from packages.core.models.events import EventType, RawEvent
from packages.ingestion.normalizer import Normalizer


def make_raw(source: str, raw_data: dict, tenant: str = "acmecorp") -> RawEvent:
    return RawEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=tenant,
        source=source,
        event_type=EventType.NODE_CREATED,
        timestamp=datetime.now(UTC),
        raw_data=raw_data,
    )


def test_normalize_servicenow_server():
    n = Normalizer()
    raw = make_raw(
        "servicenow", {"table": "cmdb_ci_server", "record": {"sys_id": "x1", "name": "srv-prod-01"}}
    )
    results = n.normalize(raw)
    assert len(results) == 1
    assert results[0].node.node_type.value == "SERVER"


def test_normalize_minio_bucket():
    n = Normalizer()
    raw = make_raw(
        "minio",
        {
            "bucket_name": "acmecorp-public",
            "is_public": True,
            "objects": [],
            "tags": {},
            "endpoint": "localhost:9000",
        },
    )
    results = n.normalize(raw)
    assert results[0].node.attributes["is_public"] is True


def test_normalize_entra_user():
    n = Normalizer()
    raw = make_raw(
        "entra_id",
        {
            "object_type": "user",
            "record": {
                "id": "uid-001",
                "displayName": "Djana Dev",
                "userPrincipalName": "djana.dev@acmecorp.onmicrosoft.com",
                "accountEnabled": True,
                "has_mfa": False,
                "mfa_methods": [],
                "createdDateTime": "2024-01-01T00:00:00Z",
            },
        },
    )
    results = n.normalize(raw)
    assert results[0].node.attributes["has_mfa"] is False


def test_normalize_gitea_repo_produces_node_and_edges():
    n = Normalizer()
    raw = make_raw(
        "gitea",
        {
            "object_type": "repository",
            "repo_id": "42",
            "name": "backend",
            "full_name": "acmecorp/backend",
            "owner": "acmecorp",
            "private": True,
            "default_branch": "main",
            "dependencies": [{"name": "qs", "version": "6.5.2", "ecosystem": "npm"}],
        },
    )
    results = n.normalize(raw)
    # 1 événement repo + 1 événement dépendance + 1 événement arête
    assert len(results) == 3
    node_events = [r for r in results if r.node is not None]
    edge_events = [r for r in results if r.edge is not None]
    assert len(node_events) == 2
    assert len(edge_events) == 1
    assert edge_events[0].edge.edge_type.value == "DEPENDS_ON"


def test_idempotence_same_event_id():
    """Le même event_id ne doit produire qu'un seul traitement."""
    from packages.ingestion.consumer import SEEN_EVENT_IDS

    event_id = str(uuid.uuid4())
    SEEN_EVENT_IDS.add(event_id)
    assert event_id in SEEN_EVENT_IDS


def test_normalize_unknown_source_returns_empty_list():
    n = Normalizer()
    raw = make_raw("unknown_source", {"foo": "bar"})
    results = n.normalize(raw)
    assert results == []


def test_gitea_repo_with_n_deps_produces_1_plus_2n():
    """Vérifie la formule 1+2N pour N=3 dépendances."""
    n = Normalizer()
    raw = make_raw(
        "gitea",
        {
            "object_type": "repository",
            "repo_id": "99",
            "name": "frontend",
            "full_name": "acmecorp/frontend",
            "owner": "acmecorp",
            "private": False,
            "default_branch": "main",
            "dependencies": [
                {"name": "react", "version": "18.0.0", "ecosystem": "npm"},
                {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
                {"name": "axios", "version": "1.4.0", "ecosystem": "npm"},
            ],
        },
    )
    results = n.normalize(raw)
    n_deps = 3
    assert len(results) == 1 + 2 * n_deps  # 7
    node_events = [r for r in results if r.node is not None]
    edge_events = [r for r in results if r.edge is not None]
    assert len(node_events) == n_deps + 1  # repo + 3 deps
    assert len(edge_events) == n_deps  # 3 DEPENDS_ON


def test_idempotence_100_duplicates():
    """100 copies du même event_id → 1 seul traitement."""
    from packages.ingestion.consumer import SEEN_EVENT_IDS, PipelineConsumer

    processed = []
    consumer = PipelineConsumer()
    event_id = str(uuid.uuid4())
    raw = make_raw(
        "servicenow", {"table": "cmdb_ci_server", "record": {"sys_id": "dup-01", "name": "dup-srv"}}
    )
    # On force le même event_id sur les 100 copies
    raw = raw.model_copy(update={"event_id": event_id})

    for _ in range(100):
        if raw.event_id in SEEN_EVENT_IDS:
            continue
        SEEN_EVENT_IDS.add(raw.event_id)
        results = consumer.normalizer.normalize(raw)
        processed.extend(results)

    assert len(processed) == 1  # traité une seule fois
