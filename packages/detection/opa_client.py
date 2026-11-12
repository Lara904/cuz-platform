# packages/detection/opa_client.py
"""Client OPA : charge les policies Rego et évalue les nœuds du graphe.
Les findings OPA sont fusionnés avec ceux des règles Cypher (DetectionRunner).

Défaillance silencieuse écartée : OPA répond HTTP 200 avec un corps `{}` (sans champ `result`) quand la
policy n'est pas chargée, par exemple après le redémarrage d'un conteneur OPA, qui garde ses policies en
mémoire. Interprété comme « aucune violation », cela donnait ZÉRO finding OPA sans la moindre erreur.

Garanties de ce module :
- `ensure_policies()` charge les policies absentes ou différentes du dépôt AVANT chaque évaluation
  (auto-réparation) et lève `OPAError` si elle n'y parvient pas ;
- `evaluate_nodes()` ne renvoie jamais une liste vide pour cause d'échec : OPA injoignable, policy refusée,
  package indéfini ou requête en erreur lèvent une `OPAError` portant les findings déjà obtenus
  (`partial_findings`), pour que l'appelant signale une détection dégradée sans perdre ces findings.
- « évalué, aucune violation » (`{"result": {}}`) reste distinct de « policy absente » (`{}`).
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

from packages.detection.models import Finding

logger = logging.getLogger(__name__)

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
POLICY_DIR = Path(__file__).resolve().parent / "rules" / "opa"
# Packages Rego évalués pour chaque nœud (règle deny[finding])
POLICY_PACKAGES = ["cuz/iam", "cuz/storage", "cuz/network", "cuz/tls", "cuz/ownership"]


class OPAError(Exception):
    """Évaluation OPA impossible ou incomplète. Le détail (URL, corps de réponse) reste dans le message,
    pour les journaux ; `summary` est la version courte, sans donnée interne, exposable via l'API."""

    summary = "évaluation impossible"

    def __init__(self, message: str, partial_findings: list[Finding] | None = None) -> None:
        super().__init__(message)
        self.partial_findings: list[Finding] = partial_findings or []


class OPAUnavailableError(OPAError):
    summary = "injoignable ou en erreur"


class OPAPolicyError(OPAError):
    summary = "policies absentes, refusées ou indéfinies"


class OPAClient:
    def __init__(
        self,
        base_url: str = OPA_URL,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport  # injectable pour les tests

    @staticmethod
    def expected_policies() -> dict[str, str]:
        """Policies du dépôt : {id: texte Rego}."""
        return {p.stem: p.read_text(encoding="utf-8") for p in sorted(POLICY_DIR.glob("*.rego"))}

    def load_policies(self) -> list[str]:
        """Pousse tous les .rego du dossier vers OPA (PUT /v1/policies/{id}), sans rien vérifier avant."""
        loaded = []
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            for pid, text in self.expected_policies().items():
                r = client.put(
                    f"{self.base_url}/v1/policies/{pid}",
                    content=text,
                    headers={"Content-Type": "text/plain"},
                )
                r.raise_for_status()
                loaded.append(pid)
        return loaded

    def ensure_policies(self) -> list[str]:
        """Garantit qu'OPA porte exactement les policies du dépôt. Charge celles qui manquent ou dont le
        texte diffère, et retourne leurs identifiants (liste vide : rien à faire).

        Lève OPAUnavailableError si OPA ne répond pas, OPAPolicyError s'il refuse une policy."""
        expected = self.expected_policies()
        if not expected:
            raise OPAPolicyError(f"aucune policy .rego dans {POLICY_DIR}")
        repaired: list[str] = []
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                r = client.get(f"{self.base_url}/v1/policies")
                r.raise_for_status()
                current = {p["id"]: p.get("raw") for p in r.json().get("result", [])}
                for pid, text in expected.items():
                    if current.get(pid) == text:
                        continue
                    put = client.put(
                        f"{self.base_url}/v1/policies/{pid}",
                        content=text,
                        headers={"Content-Type": "text/plain"},
                    )
                    if put.status_code >= 400:
                        raise OPAPolicyError(
                            f"OPA a refusé la policy {pid} (HTTP {put.status_code}) : {put.text[:300]}"
                        )
                    repaired.append(pid)
        except httpx.HTTPError as e:
            raise OPAUnavailableError(f"OPA injoignable ({self.base_url}) : {e}") from e
        except ValueError as e:  # réponse non JSON
            raise OPAUnavailableError(f"réponse illisible d'OPA ({self.base_url}) : {e}") from e
        if repaired:
            logger.warning("OPA : policies absentes ou obsolètes rechargées : %s", repaired)
        return repaired

    def evaluate_nodes(self, nodes: list[dict[str, Any]]) -> list[Finding]:
        """nodes : dicts {id, tenant_id, name, node_type, attributes, tags, owner}.

        Lève OPAError si l'évaluation n'a pas pu aller au bout (voir l'en-tête du module)."""
        self.ensure_policies()
        findings: list[Finding] = []
        failures: list[str] = []
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            for node in nodes:
                for package in POLICY_PACKAGES:
                    try:
                        r = client.post(
                            f"{self.base_url}/v1/data/{package}/deny",
                            json={"input": {"node": node}},
                        )
                        r.raise_for_status()
                        body = r.json()
                    except httpx.HTTPStatusError as e:
                        failures.append(f"{package} HTTP {e.response.status_code} ({node['id']})")
                        continue
                    except httpx.HTTPError as e:  # transport : inutile d'insister nœud par nœud
                        raise OPAUnavailableError(
                            f"OPA injoignable pendant l'évaluation ({package}, {node['id']}) : {e}",
                            findings,
                        ) from e
                    except ValueError:
                        failures.append(f"{package} réponse illisible ({node['id']})")
                        continue
                    if "result" not in body:
                        raise OPAPolicyError(
                            f"package {package} indéfini dans OPA : policy non chargée ?", findings
                        )
                    for res in _deny_items(body["result"]):
                        findings.append(
                            Finding(
                                tenant_id=node["tenant_id"],
                                rule_id=res["rule_id"],
                                severity=res["severity"],
                                title=res["title"],
                                description=res["description"],
                                affected_nodes=[node["id"]],
                                affected_node_names=[node["name"]],
                                remediation_hint=res["remediation_hint"],
                            )
                        )
        if failures:
            raise OPAUnavailableError(
                f"{len(failures)} requête(s) OPA en échec : {'; '.join(failures[:3])}", findings
            )
        return findings


def _deny_items(result: Any) -> list[dict[str, Any]]:
    """OPA sérialise un ensemble d'objets (deny[finding]) en dict dont les clés
    sont les JSON des objets ; une liste est acceptée aussi."""
    if not result:
        return []
    if isinstance(result, dict):
        return [json.loads(key) for key in result]
    return list(result)
