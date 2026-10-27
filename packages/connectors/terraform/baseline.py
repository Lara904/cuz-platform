# packages/connectors/terraform/baseline.py
"""Baseline de drift IaC (P2.3) : mesure sur le graphe la part des ressources de stockage
réelles qui ne sont pas gérées par Terraform.

Périmètre : nœuds STORAGE (buckets). Ressources réelles = STORAGE hors source terraform.
Ressources IaC = STORAGE tagués iac_managed. Lecture seule ; le résultat est écrit dans
docs/drift-baseline.json.

Usage : python -m packages.connectors.terraform.baseline --tenant acmecorp
"""
import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv

from packages.connectors.terraform.mapper import compute_drift
from packages.graph.client import Neo4jClient

OUTPUT = Path(__file__).resolve().parents[3] / "docs" / "drift-baseline.json"


def measure(tenant_id: str) -> dict:
    with Neo4jClient.get_driver().session() as session:
        real = {r["name"] for r in session.run(
            "MATCH (n:CuzNode {tenant_id: $t, node_type: 'STORAGE'}) "
            "WHERE NOT 'terraform' IN n.sources RETURN n.name AS name", t=tenant_id).data()}
        iac = {r["name"] for r in session.run(
            "MATCH (n:CuzNode {tenant_id: $t, node_type: 'STORAGE', iac_managed: true}) "
            "RETURN n.name AS name", t=tenant_id).data()}
    result = compute_drift(iac, real)
    result.update({"tenant": tenant_id, "scope": "STORAGE",
                   "measured_at": datetime.now(UTC).isoformat()})
    return result


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    result = measure(args.tenant)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
