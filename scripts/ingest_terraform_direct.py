"""
Diagnostic + ingestion directe des ressources Terraform, SANS passer par Kafka.

Pourquoi ce script : run_scan.py (connecteurs -> Kafka -> Normalizer -> GraphWriter)
publie bien "[terraform] 7 RawEvents publiés", mais aucune trace des types aws_* n'a
été retrouvée dans cuz.raw.acmecorp ni cuz.normalized.acmecorp, et aucun nœud ROLE/
NETWORK/CERTIFICATE n'apparaît dans Neo4j. Ce script appelle directement
TerraformConnector -> Normalizer -> GraphWriter._upsert_node, en mémoire, sans Kafka :
- si les nœuds apparaissent après ce script : le bug est dans la tuyauterie Kafka
  (partitionnement, timing, ou la commande rpk utilisée pour inspecter), pas dans le
  code de mapping/écriture (déjà testé unitairement).
- si ça échoue : on aura une vraie exception Python à regarder, au lieu d'un silence.

Usage :
    python scripts/ingest_terraform_direct.py
"""

import logging

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from packages.connectors.terraform.connector import TerraformConnector  # noqa: E402
from packages.graph.writer import GraphWriter  # noqa: E402
from packages.ingestion.normalizer import Normalizer  # noqa: E402

TENANT = "acmecorp"


def main() -> None:
    import asyncio

    connector = TerraformConnector(tenant_id=TENANT, config={})
    logger.info("Lecture du tfstate : %s", connector.path)
    raw_events = asyncio.run(connector.pull_full())
    logger.info("%d RawEvents Terraform lus", len(raw_events))

    normalizer = Normalizer()
    writer = GraphWriter()  # ouvre une connexion Neo4j réelle (NEO4J_URI du .env)

    written, skipped = 0, 0
    with writer.driver.session() as session:
        for raw in raw_events:
            resource = raw.raw_data["resource"]
            events = normalizer.normalize(raw)
            if not events:
                logger.warning(
                    "AUCUN NormalizedEvent produit pour %s.%s (type non mappé ou attributs "
                    "insuffisants) — c'est le symptôme exact qu'on cherchait si ça arrive ici",
                    resource["type"],
                    resource["name"],
                )
                skipped += 1
                continue
            for event in events:
                if event.node is None:
                    continue
                logger.info(
                    "-> écriture nœud %s (%s) attrs=%s",
                    event.node.name,
                    event.node.node_type.value,
                    event.node.attributes,
                )
                writer._upsert_node(session, event)  # même code que le pipeline réel
                written += 1

    logger.info(
        "Bilan : %d nœud(s) écrit(s), %d ressource(s) sans événement produit", written, skipped
    )


if __name__ == "__main__":
    main()
