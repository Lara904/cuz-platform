# services/api/routers/tenant_onboarding.py
"""
P2.14 — Orchestration de l'onboarding d'un nouveau tenant (POST /api/v1/tenants/onboard).

Écarts assumés par rapport au guide P2.14 (voir DECISIONS.md, DEC-010) :

1. Réutilise `tenants.insert_tenant_row` au lieu de dupliquer l'INSERT
   PostgreSQL de POST /api/v1/tenants (P0.8) — un seul mécanisme de création
   de tenant dans tout le projet, même principe que l'export ESA unique de
   P2.13 (DEC-008 point 5).
2. Le champ `display_name` du guide est remplacé par `name`, pour réutiliser
   TenantCreate (services/api/models/tenant.py) telle quelle plutôt que de
   réintroduire un second nom de champ pour le même concept.
3. Les étapes de provisioning (namespace k3d, policy Vault) sont RÉELLEMENT
   exécutées (appels réels au client Kubernetes / à hvac), pas des steps
   "done" fictifs comme dans le guide — cohérent avec la mise en opérationnalité
   réelle des agents en P2.11bis (DEC-006) : jamais fabriquer un résultat.
   Si la configuration (KUBECONFIG_PATH / VAULT_ADDR+VAULT_TOKEN) est absente,
   l'étape est marquée "skipped" explicitement, jamais "done".
4. La policy Vault provisionnée ici (`cuz-tenant-{tenant_id}`, KV scopé
   `cuz/tenants/{tenant_id}/*`) est une DIMENSION TENANT, distincte des
   policies par type d'agent de P2.11 (`cuz-agent-iam` etc., infra/vault/policies/),
   qui restent aujourd'hui partagées entre tous les tenants (aucune notion de
   tenant dans leur chemin Vault). Étendre les policies d'agent pour qu'elles
   soient scopées À LA FOIS par agent ET par tenant est un vrai chantier
   d'architecture (toucherait VaultJITClient et les 3 agents de P2.11bis),
   explicitement hors des critères de sortie P2.14 tels que donnés par Lara —
   documenté ici comme limite assumée, pas comme un correctif silencieux.
5. `register_connectors` reste `pending_credentials`, honnêtement : aucune
   automatisation possible sans les crédentials clients du nouveau tenant.
"""

import logging
import os
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from services.api.middleware.auth import Role, TokenData, require_role
from services.api.models.tenant import TenantCreate
from services.api.routers.tenants import TenantAlreadyExistsError, insert_tenant_row

router = APIRouter(prefix="/api/v1/tenants", tags=["tenant-onboarding"])
logger = logging.getLogger(__name__)


class TenantOnboardRequest(TenantCreate):  # type: ignore[misc, unused-ignore]  # pydantic absent de l'env mypy : BaseModel Any
    k8s_namespace: str = Field(
        ...,
        pattern=r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$",
        min_length=1,
        max_length=63,
        description="Namespace Kubernetes dédié à ce tenant (label RFC 1123)",
        examples=["acmecorp-pilot"],
    )


class OnboardStep(BaseModel):  # type: ignore[misc, unused-ignore]  # pydantic absent de l'env mypy : BaseModel Any
    step: str
    status: str
    detail: str | None = None


class TenantOnboardResponse(BaseModel):  # type: ignore[misc, unused-ignore]  # pydantic absent de l'env mypy : BaseModel Any
    tenant_id: str
    steps: list[OnboardStep]
    onboarding_duration_seconds: float


def _provision_k8s_namespace(namespace: str) -> OnboardStep:
    """Crée réellement le namespace k3d (idempotent : 409/AlreadyExists == succès).
    Nécessite KUBECONFIG_PATH pointant vers un kubeconfig capable d'écrire
    (pas le kubeconfig `cuz-reader` en lecture seule de DEC-005 — utiliser par
    exemple celui de `k3d kubeconfig get acmecorp`, déjà la solution retenue
    pour KubernetesAgent en DEC-006)."""
    kubeconfig = os.getenv("KUBECONFIG_PATH")
    if not kubeconfig:
        return OnboardStep(
            step="provision_k8s_namespace",
            status="skipped",
            detail="KUBECONFIG_PATH non configuré — namespace non provisionné",
        )
    try:
        from kubernetes import client, config
        from kubernetes.client.exceptions import ApiException

        config.load_kube_config(config_file=kubeconfig)  # type: ignore[no-untyped-call, unused-ignore]
        core_v1 = client.CoreV1Api()
        try:
            core_v1.create_namespace(
                client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )
        except ApiException as exc:
            if exc.status != 409:  # 409 = namespace déjà existant : idempotent, pas une erreur
                raise
        return OnboardStep(step="provision_k8s_namespace", status="done", detail=namespace)
    except Exception as exc:
        logger.warning("Onboarding : namespace k3d '%s' non provisionné (%s)", namespace, exc)
        return OnboardStep(step="provision_k8s_namespace", status="failed", detail=str(exc))


def _provision_vault_role(tenant_id: str) -> OnboardStep:
    """Policy Vault réellement créée, scopée par tenant (KV cuz/tenants/{tenant_id}/*).
    Voir le point 4 du docstring de module pour la limite assumée vis-à-vis
    des policies par agent de P2.11."""
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    if not vault_addr or not vault_token:
        return OnboardStep(
            step="provision_vault_role",
            status="skipped",
            detail="VAULT_ADDR/VAULT_TOKEN non configurés — policy non provisionnée",
        )
    try:
        import hvac

        policy_name = f"cuz-tenant-{tenant_id}"
        policy_hcl = f'path "cuz/tenants/{tenant_id}/*" {{\n  capabilities = ["read", "list"]\n}}\n'
        vclient = hvac.Client(url=vault_addr, token=vault_token)
        vclient.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)
        return OnboardStep(step="provision_vault_role", status="done", detail=policy_name)
    except Exception as exc:
        logger.warning(
            "Onboarding : policy Vault du tenant '%s' non provisionnée (%s)", tenant_id, exc
        )
        return OnboardStep(step="provision_vault_role", status="failed", detail=str(exc))


@router.post(  # type: ignore[misc, untyped-decorator, unused-ignore]  # fastapi absent de l'env mypy : décorateur Any
    "/onboard",
    response_model=TenantOnboardResponse,
    status_code=status.HTTP_201_CREATED,
)
async def onboard_tenant(
    req: TenantOnboardRequest,
    current_user: TokenData = Depends(require_role(Role.TENANT_ADMIN)),
) -> TenantOnboardResponse:
    """Orchestration minimale de l'onboarding : création du tenant (réutilise
    la même insertion que POST /api/v1/tenants), provisioning du namespace k3d
    dédié, policy Vault scopée par tenant, sans partage d'index Neo4j avec les
    autres tenants (toutes les requêtes restent filtrées par tenant_id, cf.
    packages/core/tenant_isolation.py)."""
    started_at = time.monotonic()
    steps: list[OnboardStep] = []

    tenant_payload = TenantCreate(id=req.id, name=req.name, description=req.description)
    try:
        await insert_tenant_row(tenant_payload)
    except TenantAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    steps.append(OnboardStep(step="create_tenant_api", status="done", detail=req.id))

    steps.append(_provision_k8s_namespace(req.k8s_namespace))
    steps.append(_provision_vault_role(req.id))
    steps.append(OnboardStep(step="register_connectors", status="pending_credentials"))

    duration_seconds = time.monotonic() - started_at
    return TenantOnboardResponse(
        tenant_id=req.id, steps=steps, onboarding_duration_seconds=duration_seconds
    )
