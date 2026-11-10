# packages/connectors/terraform/baseline.py
"""Baseline de drift IaC (P2.3), sur tout le parc connu du graphe.

Types comparés :
- STORAGE (buckets MinIO, etc.) : clé « STORAGE:<nom> » ;
- Deployments Kubernetes : clé « DEPLOYMENT:<namespace>/<nom> », côté réel via l'owner des pods
  (ReplicaSet → Deployment) ; seuls les pods frais (freshness ≥ 0.8) comptent.

Ressource gérée par IaC = nœud tagué iac_managed (writer : propriété native).
Ressource réelle = nœud hors source terraform.

Usage : python -m packages.connectors.terraform.baseline --tenant acmecorp
Résultat écrit dans docs/drift-baseline.json.
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
FRESH_THRESHOLD = 0.8


def _namespace(attrs_raw: str | None) -> str:
    import json as _json
    try:
        return (_json.loads(attrs_raw or "{}").get("namespace")) or "default"
    except _json.JSONDecodeError:
        return "default"


def build_keys(iac_rows: list[dict], real_rows: list[dict]) -> tuple[set[str], set[str]]:
    """iac_rows / real_rows : dicts {node_type, name, attrs, owner_deployment, freshness}."""
    iac: set[str] = set()
    for r in iac_rows:
        if r["node_type"] == "STORAGE":
            iac.add(f"STORAGE:{r['name']}")
        elif r["node_type"] == "CONTAINER":
            iac.add(f"DEPLOYMENT:{_namespace(r['attrs'])}/{r['name']}")
    real: set[str] = set()
    for r in real_rows:
        if r["node_type"] == "STORAGE":
            real.add(f"STORAGE:{r['name']}")
        elif r["node_type"] == "CONTAINER" and r.get("owner_deployment") \
                and (r.get("freshness") or 0) >= FRESH_THRESHOLD:
            real.add(f"DEPLOYMENT:{_namespace(r['attrs'])}/{r['owner_deployment']}")
    return iac, real


def measure(tenant_id: str) -> dict:
    with Neo4jClient.get_driver().session() as session:
        iac_rows = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) WHERE n.iac_managed = true "
            "RETURN n.node_type AS node_type, n.name AS name, n.attributes AS attrs, "
            "n.owner_deployment AS owner_deployment, n.freshness_score AS freshness",
            t=tenant_id).data()
        real_rows = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) WHERE NOT 'terraform' IN n.sources "
            "AND n.node_type IN ['STORAGE', 'CONTAINER'] "
            "RETURN n.node_type AS node_type, n.name AS name, n.attributes AS attrs, "
            "n.owner_deployment AS owner_deployment, n.freshness_score AS freshness",
            t=tenant_id).data()
    iac, real = build_keys(iac_rows, real_rows)
    result = compute_drift(iac, real)
    result.update({
        "tenant": tenant_id,
        "scope": ["STORAGE", "DEPLOYMENT"],
        "fresh_threshold": FRESH_THRESHOLD,
        "measured_at": datetime.now(UTC).isoformat(),
    })
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
