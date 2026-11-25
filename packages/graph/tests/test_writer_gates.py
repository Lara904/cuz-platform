# packages/graph/tests/test_writer_gates.py
# Tests unitaires du writer sans Neo4j ni Kafka : seuil de confiance (quarantaine)
# et éclatement de la criticité DICT en propriétés natives.
from datetime import UTC, datetime
from unittest.mock import MagicMock

from packages.core.models.enums import NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.models.node import CuzNode
from packages.graph.writer import CONFIDENCE_THRESHOLD, UPSERT_NODE_CYPHER, GraphWriter

TENANT = "acmecorp"


def _writer() -> GraphWriter:
    writer = object.__new__(GraphWriter)  # évite la connexion Neo4j / Kafka
    writer.producer = MagicMock()
    return writer


def _event(confidence: float) -> NormalizedEvent:
    node = CuzNode(
        tenant_id=TENANT,
        node_type=NodeType.USER,
        name="djana",
        external_id="u1",
        confidence_score=confidence,
        freshness_score=1.0,
        attributes={"has_mfa": False},
    )
    return NormalizedEvent(
        event_id="evt-1",
        raw_event_id="raw-1",
        tenant_id=TENANT,
        source="entra_id",
        event_type=EventType.NODE_CREATED,
        timestamp=datetime.now(UTC),
        node=node,
    )


def test_threshold_is_0_7():
    assert CONFIDENCE_THRESHOLD == 0.7


def test_quarantine_publishes_to_quarantine_topic():
    writer = _writer()
    writer._quarantine(_event(0.5))
    topic = writer.producer.produce.call_args.kwargs["topic"]
    assert topic == f"cuz.quarantine.{TENANT}"


def test_native_attrs_splits_criticality_dict():
    writer = _writer()
    native = writer._native_attrs(
        {
            "has_mfa": False,
            "criticality": {"D": 3, "I": 2, "C": 4, "T": None},
        }
    )
    assert native == {
        "has_mfa": False,
        "criticality_D": 3,
        "criticality_I": 2,
        "criticality_C": 4,
    }


def test_native_attrs_without_criticality():
    writer = _writer()
    assert writer._native_attrs({"criticality": None, "owner": "dsi"}) == {"owner": "dsi"}


def _set_clause(cypher: str, clause: str) -> str:
    """Extrait le bloc `ON CREATE SET ... ON MATCH SET` / `ON MATCH SET ... RETURN`."""
    start = cypher.index(clause) + len(clause)
    end_markers = ["ON MATCH SET", "RETURN"]
    end = min(cypher.index(m, start) for m in end_markers if m in cypher[start:])
    return cypher[start:end]


def test_upsert_node_cypher_updates_node_type_on_match():
    """Régression (DEC-012) : n.node_type doit être posé aussi bien à la création
    qu'à la mise à jour d'un nœud existant, sinon un node_type corrigé côté mapper
    (ex : ServiceNow cmdb_ci_service requalifié en BUSINESS_FUNCTION) ne peut jamais
    rattraper un nœud déjà présent dans le graphe -- il reste figé sur son tout
    premier node_type pour toujours, quelles que soient les ré-ingestions
    ultérieures. Bug découvert en vérifiant DORA-CONCENTRATION-001 sur le PDI réel
    de Lara : le node_type restait APPLICATION malgré le fix du mapper et un
    rebuild complet des pods."""
    on_create = _set_clause(UPSERT_NODE_CYPHER, "ON CREATE SET")
    on_match = _set_clause(UPSERT_NODE_CYPHER, "ON MATCH SET")
    assert "n.node_type" in on_create
    assert "n.node_type" in on_match, (
        "ON MATCH SET doit aussi poser n.node_type -- sinon le node_type d'un "
        "nœud déjà créé ne peut plus jamais être corrigé par une ré-ingestion."
    )
