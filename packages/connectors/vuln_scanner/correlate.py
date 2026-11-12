# packages/connectors/vuln_scanner/correlate.py
"""Corrélation CVE ↔ dépendances du graphe : arêtes AFFECTS (P2.4).

Une CVE (source vuln_scanner) affecte un nœud de dépendance (source gitea, ex. qs@6.5.2) quand le
package est le même et que la version tombe dans `version_affected` (ex. "<6.7.3"). Le chemin
CVE → dépendance → CONTAINER est ensuite complété par l'AFFECTS de kubernetes/correlate.

Les arêtes sont publiées sur cuz.normalized (règle 1) : le GraphWriter les écrit.

Usage : python -m packages.connectors.vuln_scanner.correlate --tenant acmecorp
"""

import argparse
import logging
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from dotenv import load_dotenv
from packaging.version import InvalidVersion, Version

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.events import EventType, NormalizedEvent
from packages.core.scoring import compute_confidence, compute_freshness

logger = logging.getLogger("vuln-correlate")

_CONSTRAINT = re.compile(r"^\s*(<=|>=|<|>|==|=)?\s*([\w.\-]+)\s*$")


@dataclass(frozen=True)
class GraphNode:
    id: str
    name: str
    attributes: dict
    sources: tuple[str, ...] = ()


def version_matches(version: str, constraint: str | None) -> bool:
    """Plage du type "<6.7.3" ou ">=1.0,<2.0". Plage absente ou illisible → False :
    on ne crée jamais une arête AFFECTS sur une hypothèse."""
    if not constraint:
        return False
    try:
        v = Version(version)
        for part in constraint.split(","):
            m = _CONSTRAINT.match(part)
            if not m:
                return False
            op, bound = m.group(1) or "==", Version(m.group(2))
            if not {
                "<": v < bound,
                "<=": v <= bound,
                ">": v > bound,
                ">=": v >= bound,
                "==": v == bound,
                "=": v == bound,
            }[op]:
                return False
        return True
    except InvalidVersion:
        return False


def correlate(cves: list[GraphNode], deps: list[GraphNode], tenant_id: str) -> list[CuzEdge]:
    """Fonction pure : CVE → dépendance quand package et plage de versions concordent."""
    edges: list[CuzEdge] = []
    now = datetime.now(UTC)
    for cve in cves:
        package = cve.attributes.get("package")
        for dep in deps:
            if not package or dep.attributes.get("package_name") != package:
                continue
            if not version_matches(
                str(dep.attributes.get("version", "")), cve.attributes.get("version_affected")
            ):
                continue
            sources = sorted({*cve.sources, *dep.sources})
            edges.append(
                CuzEdge(
                    tenant_id=tenant_id,
                    edge_type=EdgeType.AFFECTS,
                    source_id=cve.id,
                    target_id=dep.id,
                    confidence_score=compute_confidence(sources),
                    freshness_score=compute_freshness(NodeType.VULNERABILITY, now),
                    sources=sources,
                    attributes={
                        "resolution_method": "package_version_match",
                        "version": dep.attributes.get("version"),
                        "version_affected": cve.attributes.get("version_affected"),
                    },
                )
            )
    return edges


def _read_graph(session, tenant_id: str) -> tuple[list[GraphNode], list[GraphNode]]:
    import json

    def parse(raw):
        try:
            return json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}

    rows = session.run(
        "MATCH (v:CuzNode {tenant_id:$t, node_type:'VULNERABILITY'}) "
        "RETURN v.id AS id, v.name AS name, v.attributes AS attrs, v.sources AS sources",
        t=tenant_id,
    ).data()
    cves, deps = [], []
    for r in rows:
        node = GraphNode(r["id"], r["name"], parse(r["attrs"]), tuple(r["sources"] or ()))
        if "vuln_scanner" in node.sources:
            cves.append(node)
        elif "gitea" in node.sources:
            deps.append(node)
    return cves, deps


def main() -> int:
    from packages.graph.client import Neo4jClient
    from packages.ingestion.producer import EventProducer

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    with Neo4jClient.get_driver().session() as session:
        cves, deps = _read_graph(session, args.tenant)
    edges = correlate(cves, deps, args.tenant)
    producer = EventProducer()
    for edge in edges:
        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            raw_event_id=f"vuln-correlate-{uuid.uuid4()}",
            tenant_id=args.tenant,
            source="vuln_scanner",
            event_type=EventType.EDGE_CREATED,
            timestamp=datetime.now(UTC),
            edge=edge,
        )
        producer.producer.produce(
            topic=f"cuz.normalized.{args.tenant}",
            key=event.raw_event_id.encode(),
            value=event.model_dump_json().encode(),
        )
    producer.flush()
    logger.info(
        "corrélation : %d arête(s) AFFECTS publiée(s) (%d CVE, %d dépendances)",
        len(edges),
        len(cves),
        len(deps),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
