# packages/graph/tests/test_graph_writer.py
import pytest, json
from packages.graph.client import Neo4jClient
from packages.core.models.enums import NodeType

TENANT = "acmecorp"

def test_neo4j_connection():
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        result = session.run("RETURN 1 AS ok")
        assert result.single()["ok"] == 1

def test_node_count_after_ingestion():
    """Après P1.7 complet : >200 nœuds AcmeCorp dans le graphe."""
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) RETURN count(n) AS cnt", t=TENANT
        )
        count = result.single()["cnt"]
        assert count > 200

def test_edge_upsert_creates_relationship():
    """Après un cycle normalize -> upsert, l'arête DEPENDS_ON existe."""
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH ()-[r:CUZ_EDGE {tenant_id:$t, edge_type:'DEPENDS_ON'}]->() "
            "RETURN count(r) AS cnt", t=TENANT
        )
        assert result.single()["cnt"] > 0

def test_native_attrs_promoted_on_user_node():
    """has_mfa doit être filtrable comme propriété native, pas seulement
    dans le blob attributes JSON."""
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (n:CuzNode {tenant_id:$t, node_type:'USER'}) "
            "WHERE n.has_mfa = false RETURN count(n) AS cnt", t=TENANT
        )
        assert result.single()["cnt"] > 0