# packages/graph/tests/test_schema.py
"""Validation que les contraintes et index Neo4j sont bien appliqués."""

import os

import pytest
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cuzpassword")


@pytest.fixture(scope="module")
def driver():
    drv = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    yield drv
    drv.close()


def get_constraints(driver):
    with driver.session() as session:
        result = session.run("SHOW CONSTRAINTS")
        return [r.data() for r in result]


def get_indexes(driver):
    with driver.session() as session:
        result = session.run("SHOW INDEXES")
        return [r.data() for r in result]


# ── Contraintes ────────────────────────────────────────────────────────────────


def test_constraint_cuz_node_unique_exists(driver):
    """Contrainte d'unicité (tenant_id, id) sur CuzNode."""
    constraints = get_constraints(driver)
    names = [c.get("name", "") for c in constraints]
    assert "cuz_node_unique" in names, (
        f"Contrainte 'cuz_node_unique' manquante. Contraintes trouvées : {names}"
    )


def test_constraint_cuz_node_external_unique_exists(driver):
    """Contrainte d'unicité (tenant_id, external_id) sur CuzNode."""
    constraints = get_constraints(driver)
    names = [c.get("name", "") for c in constraints]
    assert "cuz_node_external_unique" in names, (
        f"Contrainte 'cuz_node_external_unique' manquante. Contraintes trouvées : {names}"
    )


def test_constraints_count(driver):
    """Au moins 2 contraintes doivent être présentes."""
    constraints = get_constraints(driver)
    cuz_constraints = [c for c in constraints if "cuz" in c.get("name", "")]
    assert len(cuz_constraints) >= 2, (
        f"Attendu >= 2 contraintes CUz, trouvé : {len(cuz_constraints)}"
    )


# ── Index ──────────────────────────────────────────────────────────────────────


def test_index_tenant_type_exists(driver):
    """Index composite tenant_id + node_type."""
    indexes = get_indexes(driver)
    names = [i.get("name", "") for i in indexes]
    assert "cuz_node_tenant_type" in names, (
        f"Index 'cuz_node_tenant_type' manquant. Index trouvés : {names}"
    )


def test_index_last_seen_exists(driver):
    """Index sur last_seen pour détection des nœuds stale."""
    indexes = get_indexes(driver)
    names = [i.get("name", "") for i in indexes]
    assert "cuz_node_last_seen" in names, (
        f"Index 'cuz_node_last_seen' manquant. Index trouvés : {names}"
    )


def test_index_freshness_exists(driver):
    """Index sur freshness_score pour les filtres dashboard."""
    indexes = get_indexes(driver)
    names = [i.get("name", "") for i in indexes]
    assert "cuz_node_freshness" in names, (
        f"Index 'cuz_node_freshness' manquant. Index trouvés : {names}"
    )


def test_index_confidence_exists(driver):
    """Index sur confidence_score pour bloquer les actions auto < 0.7."""
    indexes = get_indexes(driver)
    names = [i.get("name", "") for i in indexes]
    assert "cuz_node_confidence" in names, (
        f"Index 'cuz_node_confidence' manquant. Index trouvés : {names}"
    )


def test_index_edge_tenant_type_exists(driver):
    """Index sur les arêtes : tenant_id + edge_type."""
    indexes = get_indexes(driver)
    names = [i.get("name", "") for i in indexes]
    assert "cuz_edge_tenant_type" in names, (
        f"Index 'cuz_edge_tenant_type' manquant. Index trouvés : {names}"
    )


def test_indexes_count(driver):
    """Au moins 5 index CUz doivent être présents."""
    indexes = get_indexes(driver)
    cuz_indexes = [i for i in indexes if "cuz" in i.get("name", "")]
    assert len(cuz_indexes) >= 5, f"Attendu >= 5 index CUz, trouvé : {len(cuz_indexes)}"
