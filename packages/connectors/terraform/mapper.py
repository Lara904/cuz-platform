# packages/connectors/terraform/mapper.py
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.core.models.enums import NodeType
from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness

# Types de ressources Terraform reconnus → type de nœud CUz.
# Les autres types sont ignorés (pas d'invention de mapping).
RESOURCE_TYPE_TO_NODE_TYPE = {
    "minio_bucket": NodeType.STORAGE,
    "kubernetes_deployment": NodeType.CONTAINER,
    # P2.3 : types cloud du spec (aucun state AcmeCorp ne les contient aujourd'hui)
    "minio_s3_bucket": NodeType.STORAGE,
    "aws_s3_bucket": NodeType.STORAGE,
    "azurerm_storage_account": NodeType.STORAGE,
    "aws_instance": NodeType.SERVER,
    # P2.10 bis (DEC-004) : fixtures fictives couvrant les 3 autres exemples Tier 1 du guide
    "aws_iam_role": NodeType.ROLE,
    "aws_security_group_rule": NodeType.NETWORK,
    "aws_acm_certificate": NodeType.CERTIFICATE,
}

# P2.10 bis : seuil au-delà duquel un rôle IAM est considéré inutilisé (IAM-STALE-ROLE-001).
ROLE_UNUSED_THRESHOLD_DAYS = 90


def _role_attributes(attrs: dict[str, Any], now: datetime) -> dict[str, Any]:
    last_used = attrs.get("last_used_date")
    if not last_used:
        return {}
    last_used_dt = datetime.fromisoformat(str(last_used).replace("Z", "+00:00"))
    age_days = (now - last_used_dt).days
    return {"role_unused_90d": age_days > ROLE_UNUSED_THRESHOLD_DAYS, "role_unused_days": age_days}


def _security_group_rule_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    from_port = attrs.get("from_port")
    to_port = attrs.get("to_port")
    protocol = attrs.get("protocol")
    cidrs = attrs.get("cidr_blocks") or []
    port_22_exposed = (
        isinstance(from_port, int)
        and isinstance(to_port, int)
        and from_port <= 22 <= to_port
        and protocol in ("tcp", "-1")
    )
    return {
        "port_22_exposed": bool(port_22_exposed),
        "is_public": "0.0.0.0/0" in cidrs,
    }


def _certificate_attributes(attrs: dict[str, Any], now: datetime) -> dict[str, Any]:
    not_after = attrs.get("not_after")
    if not not_after:
        return {}
    not_after_dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    return {"cert_expired": not_after_dt < now}


# P2.10 bis : attributs dérivés (booléens prêts pour un filtre Cypher natif, cf. FIX-3 du
# GraphWriter) par type de ressource. Rien n'est deviné : une fixture sans l'attribut source
# attendu (last_used_date, cidr_blocks, not_after) ne produit simplement aucun dérivé.
DERIVED_ATTRIBUTES: dict[str, Any] = {
    "aws_iam_role": _role_attributes,
    "aws_security_group_rule": lambda attrs, _now: _security_group_rule_attributes(attrs),
    "aws_acm_certificate": _certificate_attributes,
}


class TerraformMapper:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def map_resource(self, resource: dict[str, Any]) -> CuzNode | None:
        node_type = RESOURCE_TYPE_TO_NODE_TYPE.get(resource["type"])
        if node_type is None:
            return None
        attrs = resource.get("attributes", {})
        # Le nom réel de la ressource : bucket pour minio, nom/domaine pour les types P2.10 bis,
        # sinon nom Terraform.
        name = (
            attrs.get("bucket") or attrs.get("domain_name") or attrs.get("name") or resource["name"]
        )
        last_seen = datetime.now(UTC)
        external_id = f"{resource['type']}.{resource['name']}"
        derive = DERIVED_ATTRIBUTES.get(resource["type"])
        derived = derive(attrs, last_seen) if derive else {}
        return CuzNode(
            tenant_id=self.tenant_id,
            node_type=node_type,
            name=name,
            external_id=external_id,
            external_ids={"terraform": external_id},
            confidence_score=compute_confidence(["terraform"]),
            freshness_score=compute_freshness(node_type, last_seen),
            sources=["terraform"],
            last_seen=last_seen,
            attributes={
                "tf_type": resource["type"],
                "namespace": attrs.get("namespace"),
                **derived,
            },
            tags={"source": "terraform", "iac_managed": "true", "tf_type": resource["type"]},
        )


def load_resources(path: Path) -> list[dict[str, Any]]:
    """Lit un fichier tfstate (version 4) et retourne les ressources aplaties."""
    state = json.loads(path.read_text(encoding="utf-8"))
    resources = []
    for res in state.get("resources", []):
        for inst in res.get("instances", []):
            resources.append(
                {
                    "type": res["type"],
                    "name": res["name"],
                    "attributes": inst.get("attributes", {}),
                }
            )
    return resources


def compute_drift(iac_names: set[str], real_names: set[str]) -> dict[str, Any]:
    """Drift entre ressources gérées par Terraform et ressources réelles observées.

    Les ensembles contiennent des clés typées « TYPE:nom » (ex: « STORAGE:acmecorp-archive »,
    « DEPLOYMENT:production/backend »), pour que buckets et Deployments ne se confondent pas.

    - resources_not_in_iac : réelles sans équivalent IaC (drift « non géré »)
    - resources_in_iac_but_missing_real : déclarées en IaC mais absentes du réel (drift « fantôme »)
    drift_rate_pct = part des ressources réelles non gérées. None si aucune ressource réelle.
    """
    not_in_iac = real_names - iac_names
    not_in_real = iac_names - real_names
    total = len(real_names)
    return {
        "real_total": total,
        "iac_total": len(iac_names),
        "drift_count": len(not_in_iac),
        "drift_rate_pct": round(100 * len(not_in_iac) / total, 1) if total else None,
        "resources_not_in_iac": sorted(not_in_iac),
        "resources_in_iac_but_missing_real": sorted(not_in_real),
    }
