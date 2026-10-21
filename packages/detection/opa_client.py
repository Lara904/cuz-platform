# packages/detection/opa_client.py
"""Client OPA : charge les policies Rego et évalue les nœuds du graphe.
Les findings OPA sont fusionnés avec ceux des règles Cypher (DetectionRunner)."""
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


class OPAClient:
    def __init__(
        self,
        base_url: str = OPA_URL,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport  # injectable pour les tests

    def load_policies(self) -> list[str]:
        """Pousse tous les .rego du dossier vers OPA (PUT /v1/policies/{id})."""
        loaded = []
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            for path in sorted(POLICY_DIR.glob("*.rego")):
                r = client.put(
                    f"{self.base_url}/v1/policies/{path.stem}",
                    content=path.read_text(encoding="utf-8"),
                    headers={"Content-Type": "text/plain"},
                )
                r.raise_for_status()
                loaded.append(path.stem)
        return loaded

    def evaluate_nodes(self, nodes: list[dict[str, Any]]) -> list[Finding]:
        """nodes : dicts {id, tenant_id, name, node_type, attributes, tags, owner}."""
        findings: list[Finding] = []
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            for node in nodes:
                for package in POLICY_PACKAGES:
                    try:
                        r = client.post(
                            f"{self.base_url}/v1/data/{package}/deny",
                            json={"input": {"node": node}},
                        )
                        r.raise_for_status()
                    except httpx.HTTPError as e:
                        logger.error("OPA %s failed for %s: %s", package, node["id"], e)
                        continue
                    for res in _deny_items(r.json().get("result")):
                        findings.append(Finding(
                            tenant_id=node["tenant_id"],
                            rule_id=res["rule_id"],
                            severity=res["severity"],
                            title=res["title"],
                            description=res["description"],
                            affected_nodes=[node["id"]],
                            affected_node_names=[node["name"]],
                            remediation_hint=res["remediation_hint"],
                        ))
        return findings


def _deny_items(result: Any) -> list[dict[str, Any]]:
    """OPA sérialise un ensemble d'objets (deny[finding]) en dict dont les clés
    sont les JSON des objets ; une liste est acceptée aussi."""
    if not result:
        return []
    if isinstance(result, dict):
        return [json.loads(key) for key in result]
    return list(result)
