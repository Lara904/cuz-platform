# packages/connectors/vuln_scanner/epss_client.py
import os

import httpx

EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")


class EPSSClient:
    """Enrichissement EPSS (FIRST.org) : probabilité d'exploitation à 30 jours, 0.0-1.0.
    Retourne None si l'API est injoignable ou ne connaît pas la CVE : l'appelant décide du repli."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.transport = transport  # injectable pour les tests

    async def get_epss(self, cve_id: str) -> dict[str, float] | None:
        try:
            async with httpx.AsyncClient(timeout=10, transport=self.transport) as client:
                r = await client.get(EPSS_API_URL, params={"cve": cve_id})
            if r.status_code != 200:
                return None
            data = r.json().get("data", [])
            if not data:
                return None
            return {"epss_score": float(data[0]["epss"]),
                    "epss_percentile": float(data[0]["percentile"])}
        except (httpx.HTTPError, ValueError, KeyError):
            return None
