# packages/connectors/gitea/connector.py
import os
import json
import asyncio
import uuid
import httpx
from datetime import datetime, timezone
from typing import AsyncIterator, List, Optional
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType

class GiteaConnector(IConnector):
    def __init__(self, tenant_id: str, base_url: str,
                 admin_token: str, org: str = "acmecorp"):
        self.tenant_id = tenant_id
        self.base_url = base_url.rstrip("/")
        self.org = org
        self.headers = {
            "Authorization": f"token {admin_token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> bool:
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as c:
            r = await c.get(f"{self.base_url}/api/v1/user")
            return r.status_code == 200

    async def _get_repos(self, client: httpx.AsyncClient) -> List[dict]:
        r = await client.get(
            f"{self.base_url}/api/v1/orgs/{self.org}/repos",
            params={"limit": 50}
        )
        r.raise_for_status()
        return r.json()

    async def _get_file(self, client: httpx.AsyncClient,
                        owner: str, repo: str, path: str) -> Optional[str]:
        r = await client.get(
            f"{self.base_url}/api/v1/repos/{owner}/{repo}/raw/{path}"
        )
        if r.status_code == 200:
            return r.text
        return None

    def _parse_dependencies(self, package_json: str,
                            requirements_txt: str) -> List[dict]:
        deps = []
        if package_json:
            try:
                pkg = json.loads(package_json)
                for name, version in {
                    **pkg.get("dependencies", {}),
                    **pkg.get("devDependencies", {}),
                }.items():
                    deps.append({
                        "name": name,
                        "version": version.lstrip("^~>="),
                        "ecosystem": "npm",
                    })
            except Exception:
                pass
        if requirements_txt:
            for line in requirements_txt.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("==")
                    deps.append({
                        "name": parts[0].strip(),
                        "version": parts[1].strip() if len(parts) > 1 else "unknown",
                        "ecosystem": "pypi",
                    })
        return deps

    async def _register_webhook(self, client: httpx.AsyncClient,
                                 owner: str, repo: str,
                                 callback_url: str) -> bool:
        existing = await client.get(
            f"{self.base_url}/api/v1/repos/{owner}/{repo}/hooks"
        )
        hooks = existing.json() if existing.status_code == 200 else []
        if any(h.get("config", {}).get("url") == callback_url for h in hooks):
            return True
        payload = {
            "active": True,
            "config": {"url": callback_url, "content_type": "json"},
            "events": ["push", "create", "delete", "pull_request"],
            "type": "gitea",
        }
        r = await client.post(
            f"{self.base_url}/api/v1/repos/{owner}/{repo}/hooks",
            json=payload
        )
        return r.status_code in (200, 201)

    async def pull_full(self) -> List[RawEvent]:
        events = []
        webhook_url = os.getenv(
            "CUZ_WEBHOOK_URL",
            "http://localhost:8000/api/v1/webhooks/gitea"
        )
        async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
            repos = await self._get_repos(client)
            for repo in repos:
                owner = repo["owner"]["login"]
                name = repo["name"]
                pkg_json = await self._get_file(client, owner, name, "package.json")
                reqs_txt = await self._get_file(client, owner, name, "requirements.txt")
                deps = self._parse_dependencies(
                    pkg_json or "", reqs_txt or ""
                )
                await self._register_webhook(client, owner, name, webhook_url)
                events.append(RawEvent(
                    event_id=str(uuid.uuid4()),
                    tenant_id=self.tenant_id,
                    source="gitea",
                    event_type=EventType.NODE_CREATED,
                    timestamp=datetime.now(timezone.utc),
                    raw_data={
                        "object_type":   "repository",
                        "repo_id":       str(repo["id"]),
                        "full_name":     repo["full_name"],
                        "name":          name,
                        "owner":         owner,
                        "private":       repo.get("private", True),
                        "default_branch": repo.get("default_branch", "main"),
                        "dependencies":  deps,
                    },
                ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        while True:
            for e in await self.pull_full():
                yield e
            await asyncio.sleep(86400)  # scan quotidien