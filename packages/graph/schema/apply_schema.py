# packages/graph/schema/apply_schema.py
"""Applique les migrations Neo4j de manière idempotente."""

import os
import re
from pathlib import Path

from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cuzpassword")


def parse_cypher_statements(cypher_text: str) -> list[str]:
    """
    Parse un fichier .cypher en statements individuels.
    - Supprime les lignes de commentaires (// ...)
    - Supprime les lignes vides
    - Découpe sur les points-virgules
    - Retourne uniquement les statements non vides
    """
    # Supprimer les commentaires de style // (toute la ligne)
    lines = cypher_text.splitlines()
    clean_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//"):
            continue  # ligne de commentaire, on ignore
        # Supprimer les commentaires en fin de ligne
        line_no_comment = re.sub(r"//.*$", "", line)
        clean_lines.append(line_no_comment)

    clean_text = "\n".join(clean_lines)

    # Découper sur les points-virgules
    raw_statements = clean_text.split(";")

    # Nettoyer et filtrer les statements vides
    statements = []
    for stmt in raw_statements:
        stmt = stmt.strip()
        if stmt:
            statements.append(stmt)

    return statements


def apply_schema() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    schema_dir = Path(__file__).parent
    migrations = sorted(schema_dir.glob("V*.cypher"))

    if not migrations:
        print("Aucun fichier de migration trouvé dans", schema_dir)
        driver.close()
        return

    with driver.session() as session:
        for migration in migrations:
            print(f"Applying {migration.name}...")
            cypher_text = migration.read_text(encoding="utf-8")
            statements = parse_cypher_statements(cypher_text)

            executed = 0
            for stmt in statements:
                try:
                    session.run(stmt)
                    executed += 1
                except Exception as e:
                    print(f"  ERREUR sur statement : {stmt[:80]}...")
                    print(f"  Détail : {e}")
                    raise

            print(f"  OK: {migration.name} ({executed} statements exécutés)")

    driver.close()
    print("Schema applied successfully.")


if __name__ == "__main__":
    apply_schema()
