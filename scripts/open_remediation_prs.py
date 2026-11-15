"""
P2.10 / P2.10 bis — ouvre de VRAIES PR Gitea pour les findings Tier 1 actuellement
ouverts sur un tenant, via l'API CUz réelle (pas de court-circuit de RÈGLE 7/3 :
c'est GitOpsPRGenerator._check_allowed qui décide, comme en production).

Prérequis (voir scripts/run_scan.py pour l'ingestion, l'API doit tourner) :
    - Les findings ont déjà été calculés : POST /api/v1/tenants/{tenant}/findings/refresh
    - .env contient GITEA_URL, GITEA_ADMIN_TOKEN, GITEA_ORG, GITEA_IAC_REPO
    - Le dépôt Gitea {GITEA_ORG}/{GITEA_IAC_REPO} contient des .tf déclarant les
      ressources visées (sinon RemediationNotApplicableError, message explicite —
      ce script ne génère jamais de code IaC, il modifie uniquement un .tf existant)

Usage :
    python scripts/open_remediation_prs.py --tenant acmecorp --token <JWT operator/admin>
    python scripts/open_remediation_prs.py --tenant acmecorp --username admin --password dev
"""

import argparse
import asyncio
import logging
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from packages.detection.models import Finding  # noqa: E402
from packages.remediation.gitops_pr_generator import (  # noqa: E402
    SUPPORTED_RULES,
    GitOpsError,
    GitOpsPRGenerator,
    RemediationNotApplicableError,
)

API_BASE = os.getenv("CUZ_API_URL", "http://localhost:8000")


def _login(username: str, password: str) -> str:
    r = httpx.post(f"{API_BASE}/auth/token", data={"username": username, "password": password})
    r.raise_for_status()
    return str(r.json()["access_token"])


def _open_findings(tenant: str, token: str) -> list[Finding]:
    headers = {"Authorization": f"Bearer {token}"}
    r = httpx.post(f"{API_BASE}/api/v1/tenants/{tenant}/findings/refresh", headers=headers)
    r.raise_for_status()
    logger.info("Détection relancée : %d findings au total", r.json()["total"])
    r = httpx.get(
        f"{API_BASE}/api/v1/tenants/{tenant}/findings/",
        headers=headers,
        params={"status": "open", "size": 100},  # max autorisé par l'API ; largement suffisant ici
    )
    r.raise_for_status()
    return [Finding(**item) for item in r.json()]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", default="acmecorp")
    parser.add_argument("--token", help="JWT déjà obtenu (sinon --username/--password)")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="dev")
    args = parser.parse_args()

    token = args.token or _login(args.username, args.password)
    findings = _open_findings(args.tenant, token)

    candidates = [f for f in findings if f.rule_id in SUPPORTED_RULES]
    logger.info(
        "%d findings ouverts, %d avec une règle à correctif IaC vérifié (%s)",
        len(findings),
        len(candidates),
        ", ".join(SUPPORTED_RULES),
    )
    if not candidates:
        logger.warning(
            "Aucun finding ouvert ne porte une règle de SUPPORTED_RULES : rien à ouvrir. "
            "Normal si aucune des 3 ressources concernées (bucket public, ssh_open_world, "
            "permanent-admin-role) n'a encore été ingérée/détectée sur ce tenant."
        )
        return

    gen = GitOpsPRGenerator(
        gitea_base_url=os.environ["GITEA_URL"],
        admin_token=os.environ["GITEA_ADMIN_TOKEN"],
        iac_repo=os.environ.get("GITEA_IAC_REPO", "infra"),
        org=os.environ.get("GITEA_ORG", "acmecorp"),
    )

    opened, reused, refused, failed = 0, 0, 0, 0
    for finding in candidates:
        label = f"{finding.rule_id} / {', '.join(finding.affected_node_names)}"
        try:
            result = await gen.generate_pr(finding)
        except PermissionError as exc:
            logger.warning("REFUSÉ (RÈGLE 7/3) %s : %s", label, exc)
            refused += 1
            continue
        except RemediationNotApplicableError as exc:
            logger.warning("PAS DE PR POSSIBLE %s : %s", label, exc)
            refused += 1
            continue
        except GitOpsError as exc:
            logger.error("ÉCHEC GITEA %s : %s", label, exc)
            failed += 1
            continue
        if result.created:
            logger.info("✅ PR OUVERTE %s -> %s", label, result.url)
            opened += 1
        else:
            logger.info("↻ PR déjà ouverte réutilisée %s -> %s", label, result.url)
            reused += 1

    logger.info(
        "Bilan : %d ouvertes, %d réutilisées, %d refusées (règle), %d échecs Gitea",
        opened,
        reused,
        refused,
        failed,
    )


if __name__ == "__main__":
    asyncio.run(main())
