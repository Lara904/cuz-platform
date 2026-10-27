# packages/detection/runner.py
import json
import logging
from dataclasses import dataclass
from typing import Any

from packages.connectors.cloud_detection.mapper import deduplicate_against_cypher_findings
from packages.detection.dedup import deduplicate
from packages.detection.models import Finding
from packages.detection.opa_client import OPAClient
from packages.detection.rules import attack_path, cis, dora, iac, iam, network, shadow_it
from packages.graph.client import Neo4jClient

logger = logging.getLogger(__name__)

ALL_RULE_MODULES = [network, iam, attack_path, dora, cis, iac, shadow_it]


class DetectionRunner:
    def __init__(self) -> None:
        self.driver = Neo4jClient.get_driver()

    def run_all(self, tenant_id: str) -> list[Finding]:
        findings: list[Finding] = []
        with self.driver.session() as session:
            for module in ALL_RULE_MODULES:
                for rule_fn in module.RULES:
                    try:
                        findings.extend(rule_fn(session, tenant_id))
                    except Exception as e:
                        logger.error("Rule %s failed: %s", rule_fn.__name__, e)
        findings.extend(self.run_opa(tenant_id))
        findings.extend(self.run_cloud_alerts(tenant_id, {f.rule_id for f in findings}))
        self._fill_confidence(tenant_id, findings)
        return deduplicate(findings)

    def _fill_confidence(self, tenant_id: str, findings: list[Finding]) -> None:
        """confidence_score d'un finding = min des confidences de ses nœuds."""
        ids = sorted({node_id for f in findings for node_id in f.affected_nodes})
        if not ids:
            return
        with self.driver.session() as session:
            rows = session.run(
                "MATCH (n:CuzNode {tenant_id: $t}) WHERE n.id IN $ids "
                "RETURN n.id AS id, n.confidence_score AS c",
                t=tenant_id, ids=ids,
            ).data()
        confidence = {r["id"]: r["c"] for r in rows if r["c"] is not None}
        for finding in findings:
            scores = [confidence[n] for n in finding.affected_nodes if n in confidence]
            finding.confidence_score = min(scores) if scores else 0.0

    def run_cloud_alerts(self, tenant_id: str, known_rule_ids: set[str]) -> list[Finding]:
        """Alertes cloud (nœuds node_subtype='cloud_alert') → findings, après déduplication
        par rule_id avec les findings Cypher et OPA : un même rule_id n'apparaît qu'une fois."""
        with self.driver.session() as session:
            rows = session.run(
                "MATCH (n:CuzNode {tenant_id: $t, node_subtype: 'cloud_alert'}) "
                "RETURN n.id AS id, n.name AS name, n.attributes AS attributes",
                t=tenant_id,
            ).data()
        nodes = []
        for row in rows:
            attrs = _load_json(row["attributes"])
            nodes.append(_CloudAlert(id=row["id"], name=row["name"], attributes=attrs))
        kept = deduplicate_against_cypher_findings(nodes, known_rule_ids)
        findings: list[Finding] = []
        for alert in kept:
            severity = alert.attributes.get("severity")
            findings.append(Finding(
                tenant_id=tenant_id,
                rule_id=alert.attributes.get("rule_id") or "CLOUD-ALERT",
                severity=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "MEDIUM",
                title=alert.name,
                description=alert.attributes.get("description") or alert.name,
                affected_nodes=[alert.id],
                affected_node_names=[alert.name],
                remediation_hint="Voir l'alerte dans Defender for Cloud (source : cloud_detection).",
            ))
        return findings

    def run_opa(self, tenant_id: str) -> list[Finding]:
        """Évalue les policies OPA sur tous les nœuds du tenant."""
        with self.driver.session() as session:
            rows = session.run(
                "MATCH (n:CuzNode {tenant_id: $t}) "
                "RETURN n.id AS id, n.tenant_id AS tenant_id, n.name AS name, "
                "n.node_type AS node_type, n.attributes AS attributes, "
                "n.tags AS tags, n.owner AS owner",
                t=tenant_id,
            ).data()
        nodes = [{
            "id": r["id"],
            "tenant_id": r["tenant_id"],
            "name": r["name"],
            "node_type": r["node_type"],
            "attributes": _load_json(r["attributes"]),
            "tags": _load_json(r["tags"]),
            "owner": r["owner"],
        } for r in rows]
        return OPAClient().evaluate_nodes(nodes)


@dataclass(frozen=True)
class _CloudAlert:
    id: str
    name: str
    attributes: dict[str, Any]


def _load_json(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}

    def run_on_mutation(self, tenant_id: str, affected_node_id: str) -> list[Finding]:
        """Phase 1 : relance toutes les règles. Filtrage fin par nœud en Phase 2."""
        return self.run_all(tenant_id)
