# packages/detection/rules/__init__.py
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from packages.detection.models import Finding, Severity


@dataclass(frozen=True)
class RuleSpec:
    """Une règle = une requête Cypher. La requête DOIT renvoyer les colonnes
    `node_ids` et `node_names` (listes) et filtrer sur tenant_id."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation_hint: str
    cypher: str


RuleFn = Callable[[Any, str], list[Finding]]


def make_rule(spec: RuleSpec) -> RuleFn:
    def rule(session: Any, tenant_id: str) -> list[Finding]:
        rows = session.run(spec.cypher, tenant_id=tenant_id).data()
        return [
            Finding(
                tenant_id=tenant_id,
                rule_id=spec.rule_id,
                severity=spec.severity,
                title=spec.title,
                description=spec.description,
                affected_nodes=list(row["node_ids"]),
                affected_node_names=list(row["node_names"]),
                remediation_hint=spec.remediation_hint,
            )
            for row in rows
        ]

    rule.__name__ = spec.rule_id.replace("-", "_")
    rule.spec = spec  # type: ignore[attr-defined]  # exposé pour le registre et les tests
    return rule
