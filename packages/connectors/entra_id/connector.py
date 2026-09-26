# packages/connectors/entra_id/connector.py
import os
import asyncio
import uuid
import httpx
from datetime import datetime, timezone
from typing import AsyncIterator, List, Optional
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

class EntraIDConnector(IConnector):
    def __init__(self, tenant_id_cuz: str, entra_tenant_id: str,
                 client_id: str, client_secret: str):
        self.tenant_id = tenant_id_cuz          # CUz tenant
        self.entra_tenant_id = entra_tenant_id  # Azure tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    async def _get_token(self) -> str:
        if self._token and self._token_expiry and                 datetime.now(timezone.utc) < self._token_expiry:
            return self._token
        url = f"https://login.microsoftonline.com/{self.entra_tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, data=data)
            r.raise_for_status()
            resp = r.json()
            self._token = resp["access_token"]
            expires_in = resp.get("expires_in", 3600)
            from datetime import timedelta
            self._token_expiry = datetime.now(timezone.utc) +                                  timedelta(seconds=expires_in - 60)
            return self._token

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{GRAPH_BASE}/organization", headers=headers)
                return r.status_code == 200
        except Exception:
            return False

    async def _get_all_pages(self, url: str) -> List[dict]:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        results = []
        async with httpx.AsyncClient(timeout=30) as client:
            while url:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                results.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
        return results

    async def _get_mfa_methods(self, user_id: str) -> List[dict]:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{GRAPH_BASE}/users/{user_id}/authentication/methods"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(url, headers=headers)
                if r.status_code == 200:
                    return r.json().get("value", [])
        except Exception:
            pass
        return []

    async def pull_full(self) -> List[RawEvent]:
        events = []
        users = await self._get_all_pages(
            f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,"
            f"accountEnabled,createdDateTime,passwordPolicies"
        )
        for user in users:
            mfa_methods = await self._get_mfa_methods(user["id"])
            strong = [m for m in mfa_methods
                      if m.get("@odata.type") not in
                      ["#microsoft.graph.passwordAuthenticationMethod"]]
            user["mfa_methods"] = mfa_methods
            user["has_mfa"] = len(strong) > 0
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="entra_id",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(timezone.utc),
                raw_data={"object_type": "user", "record": user},
            ))
        sps = await self._get_all_pages(
            f"{GRAPH_BASE}/servicePrincipals?$select=id,displayName,"
            f"appId,accountEnabled,passwordCredentials"
        )
        for sp in sps:
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="entra_id",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(timezone.utc),
                raw_data={"object_type": "service_principal", "record": sp},
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        while True:
            for e in await self.pull_full():
                yield e
            await asyncio.sleep(21600)  # poll 6h