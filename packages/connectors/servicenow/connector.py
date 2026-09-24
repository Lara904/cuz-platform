# packages/connectors/servicenow/connector.py
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, List, Optional

import httpx

from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType
from packages.connectors.servicenow.mapper import ServiceNowMapper

CMDB_TABLES = [
    "cmdb_ci_server",
    "cmdb_ci_appl",
    "cmdb_ci_database",
    "cmdb_ci_ip_network",
    "cmdb_ci_service",
    "cmdb_rel_ci",
]


class ServiceNowConnector(IConnector):
    """
    Connecteur ServiceNow — authentification OAuth 2.0 (password grant).

    ServiceNow exige 4 éléments pour le password grant :
      - client_id / client_secret : créés dans System OAuth > Application Registry
      - username / password        : compte admin (ou compte de service dédié)

    Le token est mis en cache et rafraîchi automatiquement avant expiration.
    """

    def __init__(
        self,
        tenant_id: str,
        instance_url: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
    ):
        self.tenant_id = tenant_id
        self.instance_url = instance_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.mapper = ServiceNowMapper(tenant_id)

        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    # ── OAuth ─────────────────────────────────────────────────────────────────

    async def _get_token(self) -> str:
        """Retourne un access_token valide, en réutilisant le cache si possible."""
        if (
            self._token
            and self._token_expiry
            and datetime.now(timezone.utc) < self._token_expiry
        ):
            return self._token

        url = f"{self.instance_url}/oauth_token.do"
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, data=data, headers=headers)
            r.raise_for_status()
            resp = r.json()

        self._token = resp["access_token"]
        expires_in = resp.get("expires_in", 1800)  # ServiceNow : 1800s par défaut
        # marge de sécurité de 60s pour éviter d'utiliser un token qui expire
        self._token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=expires_in - 60
        )
        return self._token

    async def _auth_headers(self) -> dict:
        token = await self._get_token()
        return {"Authorization": f"Bearer {token}"}

    # ── Contrat IConnector ────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        url = f"{self.instance_url}/api/now/table/cmdb_ci_server"
        params = {"sysparm_limit": 1, "sysparm_fields": "sys_id"}
        headers = await self._auth_headers()
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, params=params, headers=headers)
            return r.status_code == 200

    async def _fetch_table(
        self,
        client: httpx.AsyncClient,
        table: str,
        updated_after: Optional[datetime] = None,
    ) -> List[dict]:
        url = f"{self.instance_url}/api/now/table/{table}"
        params = {
            "sysparm_limit": 500,
            "sysparm_display_value": "false",
        }
        if updated_after:
            ts = updated_after.strftime("%Y-%m-%d %H:%M:%S")
            params["sysparm_query"] = f"sys_updated_on>{ts}"
        results = []
        offset = 0
        while True:
            params["sysparm_offset"] = offset
            # header rafraîchi à chaque page : couvre un scan long qui dépasse
            # la durée de vie du token
            headers = await self._auth_headers()
            r = await client.get(url, params=params, headers=headers)
            r.raise_for_status()
            batch = r.json().get("result", [])
            results.extend(batch)
            if len(batch) < 500:
                break
            offset += 500
        return results

    async def pull_full(self) -> List[RawEvent]:
        events = []
        async with httpx.AsyncClient(timeout=30) as client:
            for table in CMDB_TABLES:
                records = await self._fetch_table(client, table)
                for rec in records:
                    events.append(
                        RawEvent(
                            event_id=str(uuid.uuid4()),
                            tenant_id=self.tenant_id,
                            source="servicenow",
                            event_type=EventType.NODE_CREATED,
                            timestamp=datetime.now(timezone.utc),
                            raw_data={"table": table, "record": rec},
                            schema_version="1.0",
                        )
                    )
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Poll delta toutes les heures; scan quotidien complet."""
        last_pull = None
        while True:
            updated_after = last_pull
            last_pull = datetime.now(timezone.utc)
            async with httpx.AsyncClient(timeout=30) as client:
                for table in CMDB_TABLES:
                    records = await self._fetch_table(client, table, updated_after)
                    for rec in records:
                        yield RawEvent(
                            event_id=str(uuid.uuid4()),
                            tenant_id=self.tenant_id,
                            source="servicenow",
                            event_type=EventType.NODE_UPDATED,
                            timestamp=datetime.now(timezone.utc),
                            raw_data={"table": table, "record": rec},
                        )
            await asyncio.sleep(3600)  # poll horaire