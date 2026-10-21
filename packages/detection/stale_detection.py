# packages/detection/stale_detection.py
"""Détection des nœuds périmés (CronJob quotidien, P1.14). Lecture seule.

Un nœud est périmé si freshness_score < 0.2 (seuil de la règle CIS-004).
Le job produit un résumé JSON par type de nœud et par source.

Usage : python -m packages.detection.stale_detection --tenant acmecorp
"""
import argparse
import json
import logging
import sys

from dotenv import load_dotenv

from packages.graph.client import Neo4jClient

load_dotenv()
logger = logging.getLogger("stale_detection")
STALE_THRESHOLD = 0.2


def run(tenant_id: str) -> dict:
    with Neo4jClient.get_driver().session() as session:
        rows = session.run(
            """MATCH (n:CuzNode {tenant_id: $t})
               WHERE n.freshness_score < $th
               RETURN n.node_type AS node_type, n.sources[0] AS source, count(*) AS stale""",
            t=tenant_id, th=STALE_THRESHOLD,
        ).data()
    summary = {
        "tenant": tenant_id,
        "threshold": STALE_THRESHOLD,
        "stale_total": sum(r["stale"] for r in rows),
        "by_type_source": [{"node_type": r["node_type"], "source": r["source"],
                            "stale": r["stale"]} for r in rows],
    }
    logger.info("stale-detection : %s", json.dumps(summary, ensure_ascii=False))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(args.tenant)
    return 0


if __name__ == "__main__":
    sys.exit(main())
