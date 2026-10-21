# packages/ingestion/sources.py
"""Fabrique des connecteurs par source (utilisée par run_scan et les CronJobs de réconciliation)."""
import logging
import os

logger = logging.getLogger(__name__)

TENANT = "acmecorp"


def build_connectors(tenant_id: str = TENANT) -> dict:
    """Instancie les connecteurs disponibles ; un connecteur mal configuré est ignoré."""
    connectors = {}
    try:
        from packages.connectors.minio_connector.connector import MinIOConnector
        connectors["minio"] = MinIOConnector(
            tenant_id=tenant_id,
            endpoint=os.getenv("MINIO_ENDPOINT", "localhost:9000"),
            access_key=os.getenv("MINIO_USER", ""),
            secret_key=os.getenv("MINIO_PASSWORD", ""),
            secure=False,
        )
    except Exception as e:
        logger.warning("MinIO ignoré : %s", e)
    try:
        from packages.connectors.gitea.connector import GiteaConnector
        connectors["gitea"] = GiteaConnector(
            tenant_id=tenant_id,
            base_url=os.getenv("GITEA_URL", "http://localhost:3000"),
            admin_token=os.getenv("GITEA_ADMIN_TOKEN", ""),
            org="acmecorp",
        )
    except Exception as e:
        logger.warning("Gitea ignoré : %s", e)
    try:
        from packages.connectors.entra_id.connector import EntraIDConnector
        connectors["entra_id"] = EntraIDConnector(
            tenant_id_cuz=tenant_id,
            entra_tenant_id=os.getenv("ENTRA_TENANT_ID", ""),
            client_id=os.getenv("ENTRA_CLIENT_ID", ""),
            client_secret=os.getenv("ENTRA_CLIENT_SECRET", ""),
        )
    except Exception as e:
        logger.warning("Entra ID ignoré : %s", e)
    try:
        from packages.connectors.servicenow.connector import ServiceNowConnector
        connectors["servicenow"] = ServiceNowConnector(
            tenant_id=tenant_id,
            instance_url=os.getenv("SERVICENOW_URL", ""),
            client_id=os.getenv("SERVICENOW_CLIENT_ID", ""),
            client_secret=os.getenv("SERVICENOW_CLIENT_SECRET", ""),
            username=os.getenv("SERVICENOW_USER", ""),
            password=os.getenv("SERVICENOW_PASSWORD", ""),
        )
    except Exception as e:
        logger.warning("ServiceNow ignoré : %s", e)
    try:
        from packages.connectors.terraform.connector import TerraformConnector
        connectors["terraform"] = TerraformConnector(tenant_id=tenant_id, config={})
    except Exception as e:
        logger.warning("Terraform ignoré : %s", e)
    return connectors
