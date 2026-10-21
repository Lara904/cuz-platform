# packages/detection/dedup.py
"""Déduplication des findings.

Clé composite : (rule_id, ensemble des affected_nodes). Parmi les findings qui
partagent la clé, on ne garde que celui de confidence_score le plus élevé.
À égalité, le premier rencontré est conservé.
"""
from packages.detection.models import Finding

FindingKey = tuple[str, tuple[str, ...]]


def fingerprint(finding: Finding) -> FindingKey:
    return (finding.rule_id, tuple(sorted(finding.affected_nodes)))


def deduplicate(findings: list[Finding]) -> list[Finding]:
    best: dict[FindingKey, Finding] = {}
    for finding in findings:
        key = fingerprint(finding)
        current = best.get(key)
        if current is None or finding.confidence_score > current.confidence_score:
            best[key] = finding
    return list(best.values())
