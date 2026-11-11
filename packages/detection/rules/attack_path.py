# packages/detection/rules/attack_path.py
import json
from typing import Any

from packages.detection.models import Finding
from packages.detection.rules import RuleSpec, make_rule

# Version réalisable en Phase 1 (3 maillons). La version à 5 maillons
# (ATTACK-PATH-001, jusqu'au pod et au bucket) dépend du connecteur Kubernetes (P2.1).
# Filtre sur le nom complet qs@6.5.2 (CVE-2022-24999) et non sur le seul package.
# P2.4 : si le scanner a relié une CVE réelle à la dépendance (AFFECTS), elle est ajoutée au
# chemin (node_ids) et détaillée dans metadata["cves"]. Sans scanner, le chemin reste détecté.
ATTACK_PATH_001_PARTIAL = RuleSpec(
    rule_id="ATTACK-PATH-001-PARTIAL",
    severity="CRITICAL",
    title="Chemin d'attaque : utilisateur sans MFA → repo → qs@6.5.2 (CVE-2022-24999)",
    description=(
        "Un utilisateur sans MFA possède un repository qui dépend de qs@6.5.2, "
        "vulnérable à CVE-2022-24999 (CVSS 9.8)."
    ),
    remediation_hint=(
        "Activer le MFA pour l'utilisateur, et mettre à jour qs vers >= 6.5.3 "
        "(ou 6.10.3+) dans le repository."
    ),
    cypher="""
MATCH (u:CuzNode {tenant_id: $tenant_id, node_type: 'USER'})
      -[:CUZ_EDGE {edge_type: 'OWNS'}]->(repo:CuzNode {node_type: 'REPOSITORY'})
      -[:CUZ_EDGE {edge_type: 'DEPENDS_ON'}]->(dep:CuzNode {node_type: 'VULNERABILITY'})
WHERE u.has_mfa = false AND dep.name = 'qs@6.5.2'
OPTIONAL MATCH (cve:CuzNode {tenant_id: $tenant_id, node_type: 'VULNERABILITY'})
               -[:CUZ_EDGE {edge_type: 'AFFECTS'}]->(dep)
WHERE 'vuln_scanner' IN cve.sources
WITH u, repo, dep, collect(cve) AS cves
RETURN [u.id, repo.id, dep.id] + [c IN cves | c.id] AS node_ids,
       [u.name, repo.name, dep.name] + [c IN cves | c.name] AS node_names,
       [c IN cves | c.attributes] AS cve_attributes
""",
)

_base_rule = make_rule(ATTACK_PATH_001_PARTIAL)


def _decode_cves(raw_attributes: list[str | None]) -> list[dict[str, Any]]:
    cves = []
    for raw in raw_attributes:
        try:
            attrs = json.loads(raw or "{}")
        except json.JSONDecodeError:
            continue
        cves.append({k: attrs.get(k) for k in
                     ("cve_id", "cvss_score", "epss_score", "epss_source", "patch_status")})
    return cves


def attack_path_001_partial(session: Any, tenant_id: str) -> list[Finding]:
    findings = _base_rule(session, tenant_id)
    for f in findings:
        f.metadata = {"cves": _decode_cves(f.metadata.pop("cve_attributes", []))}
    return findings


attack_path_001_partial.__name__ = _base_rule.__name__
attack_path_001_partial.spec = ATTACK_PATH_001_PARTIAL  # type: ignore[attr-defined]

RULES = [attack_path_001_partial]
