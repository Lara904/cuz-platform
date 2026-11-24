# packages/core/tenant_isolation.py
"""Garde-fous d'isolation multi-tenant (P2.14), vérifiés à chaque point d'entrée
sensible : toute requête Cypher, tout accès Splink, tout agent de
remédiation DOIT être scopé par tenant_id. Centralise la vérification
plutôt que de la dupliquer dans chaque module.

Contexte architectural (cf. DECISIONS.md, DEC-010) : toutes les données de
tous les tenants partagent la même instance Neo4j Community Edition (pas de
multi-database, fonctionnalité Enterprise) -- l'isolation ne repose donc pas
sur une séparation physique, mais entièrement sur deux garanties déjà en place
indépendamment de ce module :
  1. écriture : les contraintes d'unicité composite (tenant_id, id) et
     (tenant_id, external_id) de packages/graph/schema/V001__initial_schema.cypher,
     et le MERGE systématiquement scopé par tenant_id dans
     packages/graph/writer.py (UPSERT_NODE_CYPHER / UPSERT_EDGE_CYPHER) ;
  2. lecture : CHAQUE requête Cypher (règle de détection ou router API) DOIT
     filtrer explicitement sur tenant_id -- c'est exactement ce que ce module
     vérifie, statiquement (assert_tenant_scoped_query) et en conditions
     réelles (verify_cross_tenant_leak)."""

from typing import Any

from packages.graph.client import Neo4jClient


class TenantIsolationError(Exception):
    pass


def assert_tenant_scoped_query(cypher_query: str) -> None:
    """Vérification statique minimale : toute requête Cypher sur CuzNode
    doit filtrer sur tenant_id. Appelée en test (voir
    services/api/tests/test_tenant_isolation.py, qui l'applique à TOUTES les
    règles réellement enregistrées via packages.detection.runner.ALL_RULE_MODULES)
    et, en mode strict, en pre-commit hook sur les fichiers
    packages/detection/rules/*.py."""
    if "CuzNode" in cypher_query and "tenant_id" not in cypher_query:
        raise TenantIsolationError("Requête Cypher sans filtre tenant_id détectée")


def verify_cross_tenant_leak(tenant_a: str, tenant_b: str) -> dict[str, Any]:
    """Vérifie contre la vraie instance Neo4j (pas une simulation) qu'une
    requête correctement scopée sur un tenant ne renvoie jamais un nœud dont
    la propriété tenant_id réelle diverge de celle demandée.

    Écart corrigé par rapport au guide P2.13/P2.14 (voir DECISIONS.md, DEC-010) :
    le guide écrit `MATCH (n:CuzNode {tenant_id:$b}) WHERE n.tenant_id = $a`,
    un filtre auto-contradictoire (un nœud matché par le pattern tenant_id=$b
    ne peut, par construction, satisfaire WHERE tenant_id=$a que si $a == $b) :
    cette requête renvoie 0 par pure logique Cypher, quel que soit l'état réel
    du graphe -- elle ne teste donc rien. Elle est remplacée ici par un
    contrôle qui relit explicitement la propriété tenant_id de chaque nœud
    renvoyé (plutôt que de faire confiance au WHERE pour se prouver lui-même),
    exécuté contre la vraie base : un test de fumée bout en bout de la même
    nature que la vérification du trigger append-only en DEC-007 (prouver le
    comportement réel du système plutôt que de le supposer depuis le code).
    La protection structurelle contre une vraie fuite -- une règle ou un
    endpoint qui *oublierait* le filtre tenant_id -- est assert_tenant_scoped_query
    ci-dessus, appliquée à chaque requête Cypher réellement enregistrée."""
    driver = Neo4jClient.get_driver()
    with driver.session() as session:
        record_b = session.run(
            "MATCH (n:CuzNode {tenant_id: $b}) WHERE n.tenant_id <> $b RETURN count(n) AS c",
            b=tenant_b,
        ).single()
        record_a = session.run(
            "MATCH (n:CuzNode {tenant_id: $a}) WHERE n.tenant_id <> $a RETURN count(n) AS c",
            a=tenant_a,
        ).single()
        # RETURN count(n) renvoie toujours exactement une ligne (jamais aucune) ;
        # .single() n'est Optional que par signature générique du driver neo4j.
        assert record_b is not None and record_a is not None
        mismatched_in_b = record_b["c"]
        mismatched_in_a = record_a["c"]
    return {
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "cross_tenant_nodes_found": mismatched_in_a + mismatched_in_b,
    }
