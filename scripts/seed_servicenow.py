"""
Seed idempotent de l'instance ServiceNow AcmeCorp (PDI de dev) :
CIs CMDB (serveurs, applications, bases, réseaux, services dont un prestataire
tiers), liens cmdb_rel_ci et utilisateurs sys_user.

Idempotent : chaque enregistrement est recherché par son nom, créé s'il manque, sinon mis à jour.

Usage :
    python scripts/seed_servicenow.py
Variables (.env) : SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD, et si présents
SERVICENOW_CLIENT_ID/SERVICENOW_CLIENT_SECRET (OAuth, cf. DEC-011).
"""
import logging
import os

import httpx
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

BASE = os.environ["SERVICENOW_URL"].rstrip("/")
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

# DEC-011 : l'auth basique est refusée sur le PDI réel de Lara (dev421064) --
# "User is not authenticated" quel que soit le mot de passe, confirmé via un appel
# httpx isolé (pas un souci d'encodage côté script). ServiceNow renvoie ce message
# générique quand l'auth basique est désactivée au niveau instance -- il faut passer
# par OAuth, exactement comme le fait déjà le vrai connecteur
# (packages/connectors/servicenow/connector.py). Si SERVICENOW_CLIENT_ID/SECRET sont
# absents du .env (autre instance où l'auth basique fonctionne encore), on retombe sur
# l'auth basique -- jamais les deux mécanismes mélangés dans un seul appel.
_CLIENT_ID = os.environ.get("SERVICENOW_CLIENT_ID")
_CLIENT_SECRET = os.environ.get("SERVICENOW_CLIENT_SECRET")


def _auth_client() -> httpx.Client:
    if _CLIENT_ID and _CLIENT_SECRET:
        token_resp = httpx.post(
            f"{BASE}/oauth_token.do",
            data={
                "grant_type": "password",
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "username": os.environ["SERVICENOW_USER"],
                "password": os.environ["SERVICENOW_PASSWORD"],
            },
            timeout=30,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["access_token"]
        return httpx.Client(headers={**HEADERS, "Authorization": f"Bearer {token}"})
    return httpx.Client(auth=(os.environ["SERVICENOW_USER"], os.environ["SERVICENOW_PASSWORD"]), headers=HEADERS)


CLIENT = _auth_client()

ENVS = ["production", "production", "production", "staging", "development"]


def _servers() -> list[dict]:
    names = [f"srv-prod-{i:02d}" for i in range(1, 16)] + [f"srv-stg-{i:02d}" for i in range(1, 6)]
    return [{"name": n, "sys_class_name": "cmdb_ci_server", "operational_status": "1",
             "environment": ENVS[i % len(ENVS)], "ip_address": f"10.20.{i // 250}.{i % 250 + 1}",
             "os": "Ubuntu 22.04 LTS" if i % 3 else "RHEL 9"}
            for i, n in enumerate(names)]


def _applications() -> list[dict]:
    names = ["backend", "frontend", "data-pipeline", "infra", "billing-api", "crm-core",
             "reporting", "auth-gateway", "notification-svc", "identity-sync"]
    return [{"name": n, "sys_class_name": "cmdb_ci_appl", "operational_status": "1",
             "environment": "production", "support_group": "Equipe Plateforme"} for n in names]


def _databases() -> list[dict]:
    names = ["db-customers", "db-billing", "db-reporting", "db-hr", "db-logs", "db-analytics"]
    return [{"name": n, "sys_class_name": "cmdb_ci_database", "operational_status": "1",
             "environment": "production"} for n in names]


def _networks() -> list[dict]:
    names = ["net-dmz", "net-internal", "net-backoffice", "net-k8s-pods", "net-mgmt"]
    return [{"name": n, "sys_class_name": "cmdb_ci_ip_network", "operational_status": "1",
             "environment": "production"} for n in names]


def _services() -> list[dict]:
    services = [{"name": "Acme-CRM", "sys_class_name": "cmdb_ci_service", "operational_status": "1",
                 "u_vendor_type": "internal", "u_exit_plan_status": "not_applicable"},
                {"name": "Acme-Payment-SaaS", "sys_class_name": "cmdb_ci_service", "operational_status": "1",
                 "u_vendor_type": "third_party", "vendor": "PaySaaS SAS",
                 "u_exit_plan_status": "draft"},
                {"name": "Acme-HR-SaaS", "sys_class_name": "cmdb_ci_service", "operational_status": "1",
                 "u_vendor_type": "third_party", "vendor": "HRCloud", "u_exit_plan_status": "none"}]
    # DEC-011 (suite) : 3 fonctions métier critiques internes, reliées à Acme-Payment-SaaS
    # plus bas (BUSINESS_FUNCTIONS_RELS), pour que DORA-CONCENTRATION-001 (seuil >= 3) ait
    # enfin un scénario réel à détecter sans dépendre uniquement du CSV manuel (P1.16).
    # business_criticality ET busines_criticality (coquille confirmée sur le PDI réel de
    # Lara, cf. mapper.py) sont posés tous les deux : selon l'instance, l'un des deux est
    # le vrai nom de champ -- l'autre est simplement ignoré par ServiceNow (champ inconnu).
    for name in ("Acme-Billing-Core", "Acme-Payroll-Processing", "Acme-Customer-Portal"):
        services.append({
            "name": name, "sys_class_name": "cmdb_ci_service", "operational_status": "1",
            "u_vendor_type": "internal", "business_criticality": "1 - most critical",
            "busines_criticality": "1 - most critical",
        })
    return services


BUSINESS_FUNCTION_RELS = [
    ("Acme-Payment-SaaS", "Acme-Billing-Core"),
    ("Acme-Payment-SaaS", "Acme-Payroll-Processing"),
    ("Acme-Payment-SaaS", "Acme-Customer-Portal"),
]


USERS = [
    ("djana.dev", "Djana", "Dev"),
    ("alice.martin", "Alice", "Martin"),
    ("bob.dupont", "Bob", "Dupont"),
    ("charlie.admin", "Charlie", "Admin"),
    ("svc.pipeline", "Service", "Pipeline"),
]


def _get(table: str, name_field: str, value: str) -> str | None:
    r = CLIENT.get(f"{BASE}/api/now/table/{table}", timeout=30,
                   params={"sysparm_query": f"{name_field}={value}", "sysparm_fields": "sys_id",
                           "sysparm_limit": 1})
    r.raise_for_status()
    result = r.json()["result"]
    return result[0]["sys_id"] if result else None


def _ensure(table: str, name_field: str, record: dict) -> str:
    """Crée le record s'il n'existe pas, sinon le met à jour (PATCH) pour que
    les champs ajoutés au seed soient appliqués aussi aux records existants."""
    existing = _get(table, name_field, record[name_field])
    if existing:
        CLIENT.patch(f"{BASE}/api/now/table/{table}/{existing}", json=record, timeout=30).raise_for_status()
        return existing
    r = CLIENT.post(f"{BASE}/api/now/table/{table}", json=record, timeout=30)
    r.raise_for_status()
    return r.json()["result"]["sys_id"]


def main() -> None:
    created: dict[str, str] = {}
    for table, records in [
        ("cmdb_ci_server", _servers()),
        ("cmdb_ci_appl", _applications()),
        ("cmdb_ci_database", _databases()),
        ("cmdb_ci_ip_network", _networks()),
        ("cmdb_ci_service", _services()),
    ]:
        for rec in records:
            created[rec["name"]] = _ensure(table, "name", rec)
        logger.info("%s : %d CIs", table, len(records))

    # Liens de dépendance : backend & frontend hébergés sur les serveurs prod,
    # bases utilisées par les applications, apps sur les réseaux.
    rels = [
        ("backend", "srv-prod-01"), ("backend", "srv-prod-02"),
        ("frontend", "srv-prod-03"), ("data-pipeline", "srv-prod-04"),
        ("billing-api", "db-billing"), ("crm-core", "db-customers"),
        ("reporting", "db-reporting"), ("data-pipeline", "db-analytics"),
        ("backend", "net-dmz"), ("frontend", "net-dmz"),
        ("Acme-CRM", "crm-core"), ("Acme-Payment-SaaS", "billing-api"),
        *BUSINESS_FUNCTION_RELS,
    ]
    rel_count = 0
    for parent, child in rels:
        if parent not in created or child not in created:
            logger.warning("lien ignoré (CI absent) : %s -> %s", parent, child)
            continue
        query = f"parent={created[parent]}^child={created[child]}"
        r = CLIENT.get(f"{BASE}/api/now/table/cmdb_rel_ci", timeout=30,
                       params={"sysparm_query": query, "sysparm_fields": "sys_id", "sysparm_limit": 1})
        r.raise_for_status()
        if not r.json()["result"]:
            CLIENT.post(f"{BASE}/api/now/table/cmdb_rel_ci", timeout=30,
                        json={"parent": created[parent], "child": created[child]}).raise_for_status()
        rel_count += 1
    logger.info("cmdb_rel_ci : %d liens", rel_count)

    for user_name, first, last in USERS:
        _ensure("sys_user", "user_name", {"user_name": user_name, "first_name": first,
                                          "last_name": last, "email": f"{user_name}@acmecorp.example"})
    logger.info("sys_user : %d utilisateurs", len(USERS))


if __name__ == "__main__":
    main()
