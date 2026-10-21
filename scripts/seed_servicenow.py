"""
Seed idempotent de l'instance ServiceNow AcmeCorp (PDI de dev) :
CIs CMDB (serveurs, applications, bases, réseaux, services dont un prestataire
tiers), liens cmdb_rel_ci et utilisateurs sys_user.

Idempotent : chaque enregistrement est recherché par son nom, créé s'il manque, sinon mis à jour.

Usage :
    python scripts/seed_servicenow.py
Variables (.env) : SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD
"""
import logging
import os

import httpx
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

BASE = os.environ["SERVICENOW_URL"].rstrip("/")
AUTH = (os.environ["SERVICENOW_USER"], os.environ["SERVICENOW_PASSWORD"])
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

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
    return services


USERS = [
    ("djana.dev", "Djana", "Dev"),
    ("alice.martin", "Alice", "Martin"),
    ("bob.dupont", "Bob", "Dupont"),
    ("charlie.admin", "Charlie", "Admin"),
    ("svc.pipeline", "Service", "Pipeline"),
]


def _get(table: str, name_field: str, value: str) -> str | None:
    r = httpx.get(f"{BASE}/api/now/table/{table}", auth=AUTH, headers=HEADERS, timeout=30,
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
        httpx.patch(f"{BASE}/api/now/table/{table}/{existing}", auth=AUTH, headers=HEADERS,
                    json=record, timeout=30).raise_for_status()
        return existing
    r = httpx.post(f"{BASE}/api/now/table/{table}", auth=AUTH, headers=HEADERS, json=record, timeout=30)
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
    ]
    rel_count = 0
    for parent, child in rels:
        if parent not in created or child not in created:
            logger.warning("lien ignoré (CI absent) : %s -> %s", parent, child)
            continue
        query = f"parent={created[parent]}^child={created[child]}"
        r = httpx.get(f"{BASE}/api/now/table/cmdb_rel_ci", auth=AUTH, headers=HEADERS, timeout=30,
                      params={"sysparm_query": query, "sysparm_fields": "sys_id", "sysparm_limit": 1})
        r.raise_for_status()
        if not r.json()["result"]:
            httpx.post(f"{BASE}/api/now/table/cmdb_rel_ci", auth=AUTH, headers=HEADERS, timeout=30,
                       json={"parent": created[parent], "child": created[child]}).raise_for_status()
        rel_count += 1
    logger.info("cmdb_rel_ci : %d liens", rel_count)

    for user_name, first, last in USERS:
        _ensure("sys_user", "user_name", {"user_name": user_name, "first_name": first,
                                          "last_name": last, "email": f"{user_name}@acmecorp.example"})
    logger.info("sys_user : %d utilisateurs", len(USERS))


if __name__ == "__main__":
    main()
