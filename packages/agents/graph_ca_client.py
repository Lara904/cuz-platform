# packages/agents/graph_ca_client.py
"""Client Microsoft Graph dédié à IAMAgent (DEC-006) pour la SEULE action qu'on autorise
sur IAM-001 : créer une policy Conditional Access imposant le MFA pour un utilisateur
précis. Authentification identique à EntraIDConnector (client_credentials, scope
`.default`) --- cf. packages/connectors/entra_id/connector.py.

Pourquoi un client dédié plutôt que d'étendre EntraIDConnector : ce connecteur est
volontairement en lecture seule (DEC-001) --- il alimente le graphe, il n'agit jamais sur
le SI. Mélanger lecture (ingestion) et écriture (remédiation) dans la même classe aurait
rendu moins visible le fait qu'une permission d'écriture Graph a été ajoutée spécifiquement
pour cet agent, avec son propre périmètre JIT (`cuz-agent-iam`).

Garde-fous assumés (DEC-006), au-delà de RÈGLE 3/7 :
- Resolution de l'utilisateur AVANT toute écriture, par displayName --- si zéro ou plusieurs
  comptes portent ce nom, on refuse (jamais d'action sur une cible ambiguë), même pattern
  que KubernetesAgent._find_pod().
- La policy créée est scopée à `includeUsers=[user_id]` --- UN SEUL utilisateur, jamais
  "All users" ni un groupe.
- Graph n'offre pas de dry-run sur cet endpoint (contrairement à l'API Kubernetes) : on
  relit la policy juste après création et on refuse de considérer l'action réussie si le
  scope réel ne correspond pas EXACTEMENT à ce qu'on vient de demander --- ne jamais faire
  confiance à une écriture non vérifiée sur une policy d'authentification.
"""

from typing import Any

import httpx

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class ConditionalAccessVerificationError(RuntimeError):
    """La policy créée ne correspond pas, à la relecture, à ce qui a été demandé."""


class GraphConditionalAccessClient:
    def __init__(
        self,
        entra_tenant_id: str,
        client_id: str,
        client_secret: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.entra_tenant_id = entra_tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._transport = transport
        self._token: str | None = None

    async def _get_token(self) -> str:
        # Pas de cache de durée de vie ici (contrairement à EntraIDConnector) --- ce client
        # ne vit que le temps d'une action JIT (quelques minutes, RÈGLE 6), jamais assez
        # longtemps pour qu'un token expire en cours de route.
        if self._token:
            return self._token
        url = f"https://login.microsoftonline.com/{self.entra_tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        async with httpx.AsyncClient(timeout=20, transport=self._transport) as client:
            r = await client.post(url, data=data)
            r.raise_for_status()
            self._token = str(r.json()["access_token"])
            return self._token

    async def find_user_id_by_display_name(self, display_name: str) -> str | None:
        """id Graph de l'utilisateur unique portant ce displayName --- None si introuvable
        ou ambigu (jamais d'action sur une cible incertaine)."""
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        safe = display_name.replace("'", "''")
        url = f"{GRAPH_BASE}/users?$filter=displayName eq '{safe}'&$select=id,displayName"
        async with httpx.AsyncClient(timeout=20, transport=self._transport) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            matches = r.json().get("value", [])
        return str(matches[0]["id"]) if len(matches) == 1 else None

    async def create_mfa_policy_for_user(self, user_id: str) -> dict[str, Any]:
        """Crée une policy Conditional Access DÉDIÉE (jamais de modification d'une policy
        existante) imposant le MFA, scopée strictement à cet utilisateur. Relit la policy
        après écriture et lève ConditionalAccessVerificationError si le scope réel diverge
        de ce qui a été demandé."""
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        body = {
            "displayName": f"cuz-jit-mfa-{user_id}",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": [user_id]},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }
        async with httpx.AsyncClient(timeout=20, transport=self._transport) as client:
            r = await client.post(
                f"{GRAPH_BASE}/identity/conditionalAccess/policies", headers=headers, json=body
            )
            r.raise_for_status()
            created = r.json()

            check = await client.get(
                f"{GRAPH_BASE}/identity/conditionalAccess/policies/{created['id']}",
                headers=headers,
            )
            check.raise_for_status()
            verified: dict[str, Any] = check.json()

        include_users = verified.get("conditions", {}).get("users", {}).get("includeUsers", [])
        controls = verified.get("grantControls", {}).get("builtInControls", [])
        if (
            verified.get("state") != "enabled"
            or include_users != [user_id]
            or "mfa" not in controls
        ):
            raise ConditionalAccessVerificationError(
                f"policy {created.get('id')} : scope inattendu à la relecture "
                f"(state={verified.get('state')!r}, includeUsers={include_users!r}, "
                f"builtInControls={controls!r}) --- refus fail-safe"
            )
        return verified
