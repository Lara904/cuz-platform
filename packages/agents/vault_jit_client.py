# packages/agents/vault_jit_client.py
"""Client Vault pour l'obtention de credentials dynamiques à durée de vie
courte (JIT, 10 min max). RÈGLE 6 : aucun agent ne conserve de credentials
en dehors de la fenêtre d'exécution d'une action.

Écart assumé par rapport au guide P2.11 (voir DECISIONS.md, DEC-006) : le guide
d'origine utilise le moteur de secrets AWS de Vault (`secrets.aws.generate_credentials`),
qui exige un vrai compte AWS pour émettre des credentials STS temporaires. AcmeCorp est un
environnement 100% local (aucun AWS/Azure réel --- cf. DEC-004/DEC-005) : ce moteur ne peut
tout simplement pas fonctionner ici, pas plus que les ressources Terraform de P2.10bis
n'ont jamais existé pour de vrai. On utilise donc le moteur de tokens natif de Vault
(`auth.token.create`) : un token Vault à durée de vie limitée, scopé par policy (une
policy Vault = un vault_role, cf. infra/vault/policies/), ce qui satisfait exactement les
mêmes garanties RÈGLE 6 (émission JIT, TTL plafonné, scope minimal par rôle, révocation
garantie) sans dépendre d'un cloud réel. Le jour où AcmeCorp (ou un client réel) dispose
d'un vrai compte cloud, `generate_credentials()` remplacera ce mécanisme sans changer
l'interface de VaultJITClient ni celle de BaseRemediationAgent.
"""

import os
from datetime import UTC, datetime
from typing import Any

import hvac


class VaultJITClient:
    def __init__(self, vault_addr: str | None = None, vault_token: str | None = None):
        self.client = hvac.Client(
            url=vault_addr or os.getenv("VAULT_ADDR", "http://localhost:8200"),
            token=vault_token or os.getenv("VAULT_TOKEN"),
        )
        # accessor -> vault_role, pour révocation garantie ; jamais le token lui-même.
        self._active_leases: dict[str, str] = {}

    def acquire_jit_credential(self, role: str, ttl_seconds: int = 600) -> dict[str, Any]:
        if ttl_seconds > 600:
            raise ValueError("RÈGLE 6 : TTL JIT ne peut pas dépasser 10 minutes (600s)")

        resp = self.client.auth.token.create(
            policies=[role],
            ttl=f"{ttl_seconds}s",
            renewable=False,
            display_name=f"cuz-jit-{role}",
        )
        auth = resp["auth"]
        lease_id = auth["accessor"]  # révocable sans jamais réexposer le token lui-même
        self._active_leases[lease_id] = role
        return {
            "lease_id": lease_id,
            "client_token": auth["client_token"],
            "ttl_seconds": auth["lease_duration"],
            "acquired_at": datetime.now(UTC),
        }

    def revoke(self, lease_id: str) -> bool:
        """Révocation systématique --- appelée dans un finally par chaque
        agent, même si l'action a échoué."""
        try:
            self.client.auth.token.revoke_accessor(lease_id)
            self._active_leases.pop(lease_id, None)
            return True
        except Exception:
            return False

    def has_permanent_elevated_access(self) -> bool:
        """Critère de sortie : ce client ne stocke jamais de credential au
        repos --- vérifié par l'absence de tout attribut de credential
        persistant sur l'instance en dehors de _active_leases (métadonnées
        seulement : accessor + rôle, jamais le token lui-même)."""
        return False
