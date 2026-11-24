# packages/connectors/servicenow/mapper.py
from datetime import UTC, datetime
from typing import Any

from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType, NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness

TABLE_TO_NODE_TYPE = {
    "cmdb_ci_server": NodeType.SERVER,
    "cmdb_ci_appl": NodeType.APPLICATION,
    "cmdb_ci_database": NodeType.DATABASE,
    "cmdb_ci_ip_network": NodeType.NETWORK,
    "cmdb_ci_service": NodeType.APPLICATION,
    "cmdb_rel_ci": None,  # arête — traité séparément
}

# Trouvé par Lara sur son PDI réel (dev421064) : connector.py interroge avec
# sysparm_display_value=false, donc business_criticality (champ OOB choice list de
# cmdb_ci_service, CSDM "Business Service") arrive en valeur brute ("1".."4"), jamais en
# libellé affiché. Mapping vers le même vocabulaire que business_process_loader.py
# (criticality_raw: "critical"/"high"/...), seul vocabulaire que DORA-CONCENTRATION-001
# sait filtrer (cf. packages/detection/rules/dora.py). Valeurs non reconnues ou absentes
# (None, "", valeur hors 1-4) : aucune promotion en BUSINESS_FUNCTION, le CI reste
# APPLICATION/THIRD_PARTY comme avant -- jamais de criticité devinée.
SERVICENOW_BUSINESS_CRITICALITY_MAP = {
    "1": "critical",  # "1 - most critical"
    "2": "high",  # "2 - somewhat critical"
    "3": "medium",  # "3 - less critical"
    "4": "low",  # "4 - not critical"
}


class ServiceNowMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_ci(self, table: str, rec: dict[str, Any]) -> CuzNode | None:
        node_type = TABLE_TO_NODE_TYPE.get(table)
        if not node_type:
            return None

        # FIX-1 : distinguer un prestataire tiers d'une application interne
        # (toute table mappée en APPLICATION), selon u_vendor_type du CI.
        if node_type == NodeType.APPLICATION and rec.get("u_vendor_type") == "third_party":
            node_type = NodeType.THIRD_PARTY

        # P2.13bis (suite) : un cmdb_ci_service interne (pas un prestataire tiers, déjà
        # écarté ci-dessus) dont business_criticality indique une criticité métier réelle
        # EST la fonction métier critique que DORA-CONCENTRATION-001 cherche -- pas une
        # simple APPLICATION. Avant ce changement, business_criticality était ignoré et
        # aucun cmdb_ci_service ne pouvait jamais satisfaire ce Finding (cf. DEC-009,
        # DEC-011) : le seul moyen de peupler un BUSINESS_FUNCTION restait le CSV manuel
        # de business_process_loader.py (P1.16).
        criticality_raw = None
        if table == "cmdb_ci_service" and node_type == NodeType.APPLICATION:
            criticality_raw = SERVICENOW_BUSINESS_CRITICALITY_MAP.get(
                str(rec.get("business_criticality") or "")
            )
            if criticality_raw in ("critical", "high"):
                node_type = NodeType.BUSINESS_FUNCTION

        name = rec.get("name") or rec.get("sys_id", "unknown")
        last_seen = datetime.now(UTC)
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=node_type,
            name=name,
            external_id=rec.get("sys_id"),
            external_ids={"servicenow": rec.get("sys_id", "")},
            confidence_score=compute_confidence(["servicenow"]),
            freshness_score=compute_freshness(node_type, last_seen),
            sources=["servicenow"],
            last_seen=last_seen,
            attributes={
                "operational_status": rec.get("operational_status"),
                "environment": rec.get("environment"),
                "sys_class_name": rec.get("sys_class_name"),
                "ip_address": rec.get("ip_address"),
                "os": rec.get("os"),
                "exit_plan_status": rec.get(
                    "u_exit_plan_status", rec.get("exit_plan_status")
                ),  # champ custom ServiceNow : préfixe u_ obligatoire
                "vendor": rec.get("vendor"),
                "support_group": rec.get("support_group"),
                "u_vendor_type": rec.get("u_vendor_type"),
                # Même clé que business_process_loader.py (P1.16) : un seul vocabulaire
                # de criticité, qu'il vienne du CSV manuel ou du CMDB ServiceNow --
                # promu en propriété Neo4j native par NATIVE_PROMOTED_KEYS
                # (packages/graph/writer.py), seule façon d'être filtrable en Cypher.
                "criticality_raw": criticality_raw,
                "business_criticality_raw": rec.get("business_criticality"),
            },
            tags={
                "source": "servicenow",
                "cmdb_table": table,
            },
        )

    def map_relationship(self, rec: dict[str, Any]) -> CuzEdge | None:
        """cmdb_rel_ci -> CuzEdge (P2.13bis, FIX-1/P1.16).

        Jusqu'ici ces enregistrements étaient silencieusement perdus : map_ci()
        renvoie None pour cette table (arête, pas nœud) et rien d'autre ne les
        traitait -- aucune relation CMDB réelle (une appli qui dépend d'une
        base, un prestataire tiers qui dépend d'une appli interne, etc.)
        n'atteignait jamais le graphe.

        Construction de l'id : le connecteur (connector.py, CMDB_TABLES) place
        cmdb_rel_ci en dernier, après les tables de CI -- les nœuds parent/
        child existent donc déjà côté graphe au moment où cette arête est
        traitée, dans le cas nominal d'un pull_full() séquentiel. Comme pour
        toute arête de ce repo, UPSERT_EDGE_CYPHER (packages/graph/writer.py)
        matche par id et ne lève aucune erreur si un nœud référencé n'existe
        pas encore : l'arête est alors silencieusement non créée (même
        comportement que les autres connecteurs, pas une limite introduite
        ici). L'id est reconstruit sans aller chercher le nœud en base, selon
        la même convention que Normalizer._stamp() : `{source}:{external_id}`,
        et external_id = sys_id pour tout nœud ServiceNow (map_ci ci-dessus).

        Limite assumée, à lever une fois un PDI accessible pour vérifier en
        conditions réelles : sysparm_display_value=false (connector.py) fait
        que `type` (référence vers cmdb_rel_type) arrive en sys_id brut,
        illisible sans une requête supplémentaire sur cmdb_rel_type. Sans
        accès à un PDI pour inspecter ce que ce champ contient réellement,
        toute relation est mappée en EdgeType.DEPENDS_ON -- la sémantique par
        défaut de ServiceNow ("Depends on::Used by") et celle de la quasi-
        totalité des relations du seed AcmeCorp (scripts/seed_servicenow.py).
        Le sys_id brut du type est conservé dans attributes pour ne pas
        perdre l'information, en vue d'un futur raffinement."""
        parent_id = rec.get("parent")
        child_id = rec.get("child")
        if not parent_id or not child_id:
            return None
        last_seen = datetime.now(UTC)
        return CuzEdge(
            tenant_id=self.tenant_id,
            edge_type=EdgeType.DEPENDS_ON,
            source_id=f"servicenow:{parent_id}",
            target_id=f"servicenow:{child_id}",
            confidence_score=compute_confidence(["servicenow"]),
            freshness_score=compute_freshness(NodeType.APPLICATION, last_seen),
            sources=["servicenow"],
            last_seen=last_seen,
            attributes={"cmdb_rel_type_sys_id": rec.get("type")},
        )
