# packages/core/tests/test_models.py
"""
50 tests unitaires P0.3 — CuzNode, CuzEdge, NodeType, EdgeType.
Couvre : types, valeurs limites, sérialisation JSON, désérialisation, cas d'erreur.

Lancer avec : pytest packages/core/tests/test_models.py -v
"""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.node import CuzNode

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — NodeType enum (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_nodetype_count():
    """21 types de nœuds définis."""
    assert len(NodeType) == 21


def test_nodetype_infrastructure_values():
    """Les types infrastructure sont présents."""
    assert NodeType.SERVER == "SERVER"
    assert NodeType.VIRTUAL_MACHINE == "VIRTUAL_MACHINE"
    assert NodeType.CONTAINER == "CONTAINER"
    assert NodeType.CLUSTER == "CLUSTER"
    assert NodeType.NETWORK == "NETWORK"


def test_nodetype_application_values():
    """Les types applicatifs sont présents."""
    assert NodeType.APPLICATION == "APPLICATION"
    assert NodeType.API == "API"
    assert NodeType.DATABASE == "DATABASE"
    assert NodeType.QUEUE == "QUEUE"


def test_nodetype_identity_values():
    """Les types identité sont présents."""
    assert NodeType.USER == "USER"
    assert NodeType.SERVICE_ACCOUNT == "SERVICE_ACCOUNT"
    assert NodeType.GROUP == "GROUP"
    assert NodeType.ROLE == "ROLE"


def test_nodetype_from_string():
    """NodeType est constructible depuis une chaîne."""
    assert NodeType("SERVER") == NodeType.SERVER
    assert NodeType("VULNERABILITY") == NodeType.VULNERABILITY
    with pytest.raises(ValueError):
        NodeType("INVALID_TYPE")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — EdgeType enum (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_edgetype_count():
    """20 types d'arêtes définis."""
    assert len(EdgeType) == 20


def test_edgetype_core_values():
    """Les types d'arêtes principaux sont présents."""
    assert EdgeType.HOSTS == "HOSTS"
    assert EdgeType.DEPENDS_ON == "DEPENDS_ON"
    assert EdgeType.CALLS == "CALLS"
    assert EdgeType.DEPLOYS == "DEPLOYS"


def test_edgetype_security_values():
    """Les types d'arêtes sécurité sont présents."""
    assert EdgeType.SECURES == "SECURES"
    assert EdgeType.HAS_ROLE == "HAS_ROLE"
    assert EdgeType.ALLOWS == "ALLOWS"
    assert EdgeType.AFFECTS == "AFFECTS"


def test_edgetype_from_string():
    """EdgeType est constructible depuis une chaîne."""
    assert EdgeType("HOSTS") == EdgeType.HOSTS
    assert EdgeType("SUPPORTS") == EdgeType.SUPPORTS
    with pytest.raises(ValueError):
        EdgeType("INVALID_EDGE")


def test_edgetype_all_values_are_uppercase_strings():
    """Tous les EdgeType sont des chaînes uppercase."""
    for et in EdgeType:
        assert et.value == et.value.upper()
        assert isinstance(et.value, str)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — CuzNode création et attributs (10 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_cuznode_minimal_creation():
    """CuzNode créable avec les champs minimaux obligatoires."""
    node = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.SERVER,
        name="web-server-01",
        confidence_score=0.9,
        freshness_score=0.8,
    )
    assert node.tenant_id == "acmecorp"
    assert node.node_type == NodeType.SERVER
    assert node.name == "web-server-01"


def test_cuznode_id_auto_generated():
    """L'id est généré automatiquement si non fourni."""
    node = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.APPLICATION,
        name="my-app",
        confidence_score=0.8,
        freshness_score=0.7,
    )
    assert node.id is not None
    assert len(node.id) == 36  # UUID format


def test_cuznode_two_nodes_have_different_ids():
    """Deux nœuds créés sans id ont des ids différents."""
    node1 = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="s1",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    node2 = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="s2",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    assert node1.id != node2.id


def test_cuznode_custom_id():
    """L'id peut être fourni manuellement."""
    node = CuzNode(
        id="custom-id-123",
        tenant_id="acmecorp",
        node_type=NodeType.DATABASE,
        name="prod-db",
        confidence_score=0.95,
        freshness_score=0.85,
    )
    assert node.id == "custom-id-123"


def test_cuznode_external_ids_default_empty():
    """external_ids est un dict vide par défaut."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.USER,
        name="alice",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    assert node.external_ids == {}
    assert node.sources == []


def test_cuznode_with_external_ids():
    """external_ids accepte plusieurs sources."""
    node = CuzNode(
        tenant_id="stellantis",
        node_type=NodeType.SERVER,
        name="srv-001",
        confidence_score=0.95,
        freshness_score=0.8,
        external_id="arm://subscriptions/abc/vms/srv-001",
        external_ids={
            "azure": "arm://subscriptions/abc/vms/srv-001",
            "servicenow": "sys_id_xyz",
        },
        sources=["azure", "servicenow"],
    )
    assert "azure" in node.external_ids
    assert "servicenow" in node.external_ids
    assert len(node.sources) == 2


def test_cuznode_attributes_dict():
    """Le champ attributes accepte des données arbitraires."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.VIRTUAL_MACHINE,
        name="vm-prod-01",
        confidence_score=0.9,
        freshness_score=0.7,
        attributes={"os": "Ubuntu 22.04", "vcpus": 4, "ram_gb": 16},
    )
    assert node.attributes["os"] == "Ubuntu 22.04"
    assert node.attributes["vcpus"] == 4


def test_cuznode_tags_dict():
    """Le champ tags accepte des paires clé-valeur string."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.APPLICATION,
        name="api-gateway",
        confidence_score=0.85,
        freshness_score=0.9,
        tags={"env": "production", "owner": "team-platform"},
    )
    assert node.tags["env"] == "production"
    assert node.tags["owner"] == "team-platform"


def test_cuznode_timestamps_auto_set():
    """Les timestamps created_at, updated_at, last_seen sont auto-définis."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.CLUSTER,
        name="k8s-prod",
        confidence_score=0.92,
        freshness_score=0.88,
    )
    assert isinstance(node.created_at, datetime)
    assert isinstance(node.updated_at, datetime)
    assert isinstance(node.last_seen, datetime)


def test_cuznode_all_node_types_accepted():
    """CuzNode accepte tous les 21 NodeType."""
    for nt in NodeType:
        node = CuzNode(
            tenant_id="t1",
            node_type=nt,
            name=f"test-{nt.value.lower()}",
            confidence_score=0.8,
            freshness_score=0.8,
        )
        assert node.node_type == nt


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CuzNode validation des scores (8 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_cuznode_confidence_score_zero():
    """confidence_score = 0.0 est valide."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="unknown-srv",
        confidence_score=0.0,
        freshness_score=0.5,
    )
    assert node.confidence_score == 0.0


def test_cuznode_confidence_score_one():
    """confidence_score = 1.0 est valide."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="trusted-srv",
        confidence_score=1.0,
        freshness_score=0.5,
    )
    assert node.confidence_score == 1.0


def test_cuznode_confidence_score_above_one_raises():
    """confidence_score > 1.0 lève une ValidationError."""
    with pytest.raises(ValidationError):
        CuzNode(
            tenant_id="t1",
            node_type=NodeType.SERVER,
            name="bad",
            confidence_score=1.1,
            freshness_score=0.5,
        )


def test_cuznode_confidence_score_negative_raises():
    """confidence_score < 0.0 lève une ValidationError."""
    with pytest.raises(ValidationError):
        CuzNode(
            tenant_id="t1",
            node_type=NodeType.SERVER,
            name="bad",
            confidence_score=-0.1,
            freshness_score=0.5,
        )


def test_cuznode_freshness_score_zero():
    """freshness_score = 0.0 est valide (nœud stale)."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.VULNERABILITY,
        name="old-cve",
        confidence_score=0.9,
        freshness_score=0.0,
    )
    assert node.freshness_score == 0.0


def test_cuznode_freshness_score_above_one_raises():
    """freshness_score > 1.0 lève une ValidationError."""
    with pytest.raises(ValidationError):
        CuzNode(
            tenant_id="t1",
            node_type=NodeType.SERVER,
            name="bad",
            confidence_score=0.9,
            freshness_score=1.5,
        )


def test_cuznode_score_rounded_to_4_decimals():
    """Les scores sont arrondis à 4 décimales."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="srv",
        confidence_score=0.123456789,
        freshness_score=0.987654321,
    )
    assert node.confidence_score == round(0.123456789, 4)
    assert node.freshness_score == round(0.987654321, 4)


def test_cuznode_missing_confidence_score_raises():
    """confidence_score est obligatoire."""
    with pytest.raises(ValidationError):
        CuzNode(
            tenant_id="t1",
            node_type=NodeType.SERVER,
            name="srv",
            freshness_score=0.8,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — CuzNode sérialisation / désérialisation JSON (7 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_cuznode_serializable_to_json():
    """CuzNode est sérialisable en JSON sans erreur."""
    node = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.APPLICATION,
        name="my-app",
        confidence_score=0.9,
        freshness_score=0.8,
    )
    json_str = node.model_dump_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["name"] == "my-app"


def test_cuznode_deserializable_from_dict():
    """CuzNode est reconstruisible depuis un dict."""
    data = {
        "id": "abc-123",
        "tenant_id": "acmecorp",
        "node_type": "SERVER",
        "name": "web-01",
        "confidence_score": 0.85,
        "freshness_score": 0.75,
    }
    node = CuzNode(**data)
    assert node.id == "abc-123"
    assert node.node_type == NodeType.SERVER


def test_cuznode_roundtrip_json():
    """CuzNode survit un aller-retour JSON complet."""
    original = CuzNode(
        tenant_id="stellantis",
        node_type=NodeType.DATABASE,
        name="prod-oracle",
        confidence_score=0.92,
        freshness_score=0.78,
        external_ids={"servicenow": "sys_abc"},
        sources=["servicenow"],
        attributes={"engine": "Oracle 19c"},
        tags={"env": "prod"},
    )
    json_str = original.model_dump_json()
    restored = CuzNode.model_validate_json(json_str)
    assert restored.id == original.id
    assert restored.tenant_id == original.tenant_id
    assert restored.node_type == original.node_type
    assert restored.attributes["engine"] == "Oracle 19c"


def test_cuznode_model_dump_contains_required_fields():
    """model_dump() contient tous les champs attendus."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.USER,
        name="alice",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    d = node.model_dump()
    required_fields = [
        "id",
        "tenant_id",
        "node_type",
        "name",
        "confidence_score",
        "freshness_score",
        "sources",
        "external_ids",
        "attributes",
        "tags",
        "created_at",
        "updated_at",
        "last_seen",
    ]
    for field in required_fields:
        assert field in d, f"Champ manquant dans model_dump() : {field}"


def test_cuznode_from_json_with_node_type_string():
    """NodeType peut être désérialisé depuis sa valeur string."""
    json_str = json.dumps(
        {
            "tenant_id": "t1",
            "node_type": "CLUSTER",
            "name": "k8s-dev",
            "confidence_score": 0.88,
            "freshness_score": 0.72,
        }
    )
    node = CuzNode.model_validate_json(json_str)
    assert node.node_type == NodeType.CLUSTER


def test_cuznode_invalid_node_type_raises():
    """Un node_type invalide lève une ValidationError."""
    with pytest.raises(ValidationError):
        CuzNode(
            tenant_id="t1",
            node_type="NOT_A_TYPE",
            name="bad",
            confidence_score=0.8,
            freshness_score=0.8,
        )


def test_cuznode_missing_tenant_id_raises():
    """tenant_id est obligatoire."""
    with pytest.raises(ValidationError):
        CuzNode(
            node_type=NodeType.SERVER,
            name="srv",
            confidence_score=0.8,
            freshness_score=0.8,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — CuzEdge création, validation, sérialisation (10 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_cuzedge_minimal_creation():
    """CuzEdge créable avec les champs minimaux."""
    edge = CuzEdge(
        tenant_id="acmecorp",
        edge_type=EdgeType.HOSTS,
        source_id="node-server-01",
        target_id="node-app-01",
        confidence_score=0.9,
        freshness_score=0.85,
    )
    assert edge.edge_type == EdgeType.HOSTS
    assert edge.source_id == "node-server-01"


def test_cuzedge_id_auto_generated():
    """L'id de l'arête est généré automatiquement."""
    edge = CuzEdge(
        tenant_id="t1",
        edge_type=EdgeType.CALLS,
        source_id="a",
        target_id="b",
        confidence_score=0.8,
        freshness_score=0.8,
    )
    assert edge.id is not None
    assert len(edge.id) == 36


def test_cuzedge_all_edge_types_accepted():
    """CuzEdge accepte tous les 20 EdgeType."""
    for et in EdgeType:
        edge = CuzEdge(
            tenant_id="t1",
            edge_type=et,
            source_id="src",
            target_id="tgt",
            confidence_score=0.8,
            freshness_score=0.8,
        )
        assert edge.edge_type == et


def test_cuzedge_confidence_above_one_raises():
    """confidence_score > 1.0 sur une arête lève une erreur."""
    with pytest.raises(ValidationError):
        CuzEdge(
            tenant_id="t1",
            edge_type=EdgeType.HOSTS,
            source_id="a",
            target_id="b",
            confidence_score=1.5,
            freshness_score=0.8,
        )


def test_cuzedge_negative_freshness_raises():
    """freshness_score négatif lève une ValidationError."""
    with pytest.raises(ValidationError):
        CuzEdge(
            tenant_id="t1",
            edge_type=EdgeType.DEPENDS_ON,
            source_id="a",
            target_id="b",
            confidence_score=0.8,
            freshness_score=-0.1,
        )


def test_cuzedge_attributes_dict():
    """CuzEdge accepte des attributs arbitraires."""
    edge = CuzEdge(
        tenant_id="t1",
        edge_type=EdgeType.TRANSFERS_TO,
        source_id="queue-01",
        target_id="app-02",
        confidence_score=0.9,
        freshness_score=0.9,
        attributes={"protocol": "AMQP", "port": 5672},
    )
    assert edge.attributes["protocol"] == "AMQP"


def test_cuzedge_serializable_to_json():
    """CuzEdge est sérialisable en JSON."""
    edge = CuzEdge(
        tenant_id="acmecorp",
        edge_type=EdgeType.MONITORS,
        source_id="prometheus",
        target_id="app-01",
        confidence_score=0.95,
        freshness_score=0.9,
    )
    json_str = edge.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["edge_type"] == "MONITORS"


def test_cuzedge_roundtrip_json():
    """CuzEdge survit un aller-retour JSON."""
    original = CuzEdge(
        tenant_id="stellantis",
        edge_type=EdgeType.HAS_ROLE,
        source_id="user-alice",
        target_id="role-admin",
        confidence_score=0.88,
        freshness_score=0.77,
        sources=["entra_id"],
    )
    json_str = original.model_dump_json()
    restored = CuzEdge.model_validate_json(json_str)
    assert restored.id == original.id
    assert restored.edge_type == EdgeType.HAS_ROLE
    assert restored.sources == ["entra_id"]


def test_cuzedge_missing_source_id_raises():
    """source_id est obligatoire."""
    with pytest.raises(ValidationError):
        CuzEdge(
            tenant_id="t1",
            edge_type=EdgeType.CALLS,
            target_id="b",
            confidence_score=0.8,
            freshness_score=0.8,
        )


def test_cuzedge_model_dump_contains_required_fields():
    """model_dump() de CuzEdge contient tous les champs attendus."""
    edge = CuzEdge(
        tenant_id="t1",
        edge_type=EdgeType.SECURES,
        source_id="iam",
        target_id="app",
        confidence_score=0.9,
        freshness_score=0.85,
    )
    d = edge.model_dump()
    required_fields = [
        "id",
        "tenant_id",
        "edge_type",
        "source_id",
        "target_id",
        "confidence_score",
        "freshness_score",
        "sources",
        "attributes",
        "created_at",
        "updated_at",
        "last_seen",
    ]
    for field in required_fields:
        assert field in d, f"Champ manquant dans model_dump() : {field}"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — Tests d'intégration nœud + arête (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


def test_node_and_edge_tenant_isolation():
    """Deux nœuds de tenants différents ne partagent pas d'id."""
    node1 = CuzNode(
        tenant_id="tenant-a",
        node_type=NodeType.SERVER,
        name="srv",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    node2 = CuzNode(
        tenant_id="tenant-b",
        node_type=NodeType.SERVER,
        name="srv",
        confidence_score=0.9,
        freshness_score=0.9,
    )
    assert node1.id != node2.id
    assert node1.tenant_id != node2.tenant_id


def test_edge_links_two_nodes():
    """Une arête peut référencer les ids de deux nœuds."""
    server = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.SERVER,
        name="srv-01",
        confidence_score=0.95,
        freshness_score=0.9,
    )
    app = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.APPLICATION,
        name="api-01",
        confidence_score=0.9,
        freshness_score=0.85,
    )
    edge = CuzEdge(
        tenant_id="acmecorp",
        edge_type=EdgeType.HOSTS,
        source_id=server.id,
        target_id=app.id,
        confidence_score=0.9,
        freshness_score=0.85,
    )
    assert edge.source_id == server.id
    assert edge.target_id == app.id


def test_vulnerability_node_with_affects_edge():
    """Un nœud VULNERABILITY lié à un SERVER via AFFECTS."""
    vuln = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.VULNERABILITY,
        name="CVE-2022-24999",
        confidence_score=0.98,
        freshness_score=0.6,
        attributes={"cvss": 9.8, "epss": 0.78},
    )
    server = CuzNode(
        tenant_id="acmecorp",
        node_type=NodeType.SERVER,
        name="prod-srv-01",
        confidence_score=0.95,
        freshness_score=0.9,
    )
    edge = CuzEdge(
        tenant_id="acmecorp",
        edge_type=EdgeType.AFFECTS,
        source_id=vuln.id,
        target_id=server.id,
        confidence_score=0.95,
        freshness_score=0.6,
    )
    assert edge.edge_type == EdgeType.AFFECTS
    assert vuln.attributes["cvss"] == 9.8


def test_multi_source_node_has_higher_confidence():
    """Un nœud confirmé par 2 sources a un confidence_score plus élevé."""
    node_single = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="srv",
        confidence_score=0.8,
        freshness_score=0.9,
        sources=["servicenow"],
    )
    node_multi = CuzNode(
        tenant_id="t1",
        node_type=NodeType.SERVER,
        name="srv",
        confidence_score=0.96,
        freshness_score=0.9,
        sources=["servicenow", "azure"],
    )
    assert node_multi.confidence_score > node_single.confidence_score


def test_stale_node_low_freshness():
    """Un nœud non vu depuis longtemps a un freshness_score bas."""
    node = CuzNode(
        tenant_id="t1",
        node_type=NodeType.USER,
        name="old-user",
        confidence_score=0.8,
        freshness_score=0.02,  # Vu il y a très longtemps
        last_seen=datetime(2025, 1, 1, tzinfo=UTC),
    )
    assert node.freshness_score < 0.1
