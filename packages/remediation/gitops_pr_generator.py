# packages/remediation/gitops_pr_generator.py
"""Génère une PR Gitea pour un finding Tier 1 (P2.10, RÈGLE 7 : seul tier autorisé en automatisation).

La PR modifie une ressource Terraform EXISTANTE du dépôt IaC (voir terraform_edit.py) : pas de code IaC
généré librement, pas de fichier à compléter à la main. Si la ressource n'est pas dans le dépôt, il n'y a
PAS de PR : c'est le sens de « si géré en IaC ».

Garde-fous :
- `can_automate_finding` : Tier 1, finding ouvert, confidence_score >= 0.7 (RÈGLE 3). Sinon PermissionError.
- une règle sans stratégie de correction vérifiée est refusée (RemediationNotApplicableError), jamais devinée ;
- jamais de merge : la PR attend une revue humaine ;
- idempotent : branche stable dérivée de l'empreinte du finding ; une PR ouverte est réutilisée, une PR
  fermée ou mergée n'est pas rouverte ;
- chaque appel Gitea est vérifié ; si une étape échoue après la création de la branche, elle est supprimée ;
- audit (RÈGLE 4) via le hook `audit` : écrit AVANT toute écriture dans Gitea (si l'audit échoue, rien n'est
  créé), puis le résultat. Le jeton Gitea n'apparaît dans aucun message d'erreur ni aucun journal.
"""

import base64
import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from packages.detection.dedup import fingerprint
from packages.detection.models import Finding
from packages.detection.tier_classifier import (
    MIN_CONFIDENCE_FOR_AUTOMATION,
    can_automate_finding,
    classify,
)
from packages.remediation.terraform_edit import (
    AlreadyClosedError,
    AlreadyPrivateError,
    HCLError,
    NonLiteralValueError,
    TerraformEdit,
    close_open_cidr,
    locate_bucket,
    locate_security_group_rule,
    make_bucket_private,
)

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
MAX_TF_FILES = 200
MAX_TF_FILE_BYTES = 1_000_000

# Types de ressources dont l'attribut `acl` pilote l'accès public (ceux que le connecteur Terraform reconnaît)
BUCKET_RESOURCE_TYPES = frozenset({"minio_s3_bucket", "minio_bucket", "aws_s3_bucket"})
# P2.10 bis (DEC-004) : règle réseau dont le CIDR pilote l'exposition du port 22
NSG_RESOURCE_TYPES = frozenset({"aws_security_group_rule"})

AuditHook = Callable[[str, str], Awaitable[None]]  # (action, détail)


class RemediationNotApplicableError(Exception):
    """Pas de PR possible, et c'est le bon résultat : le message dit pourquoi (sans donnée interne)."""


class GitOpsError(Exception):
    """Échec d'un appel Gitea. `step` et `status` sont exposables ; le détail reste dans le message."""

    def __init__(self, step: str, status: int | None, detail: str = "") -> None:
        super().__init__(
            f"Gitea {step} : " + (f"HTTP {status}" if status else "injoignable") + detail
        )
        self.step = step
        self.status = status


@dataclass(frozen=True)
class PullRequestResult:
    number: int
    url: str
    branch: str
    file_path: str
    created: bool  # False : PR déjà ouverte réutilisée


# Règles Tier 1 pour lesquelles une correction IaC vérifiée existe dans ce SI.
SUPPORTED_RULES: dict[str, str] = {
    "STORAGE-PUBLIC-001": "CIS 2.1.1 (buckets privés par défaut) / DORA Art. 9 (protection des données)",
    # P2.10 bis (DEC-004) : fixtures fictives AcmeCorp, correctif déterministe vérifié (terraform_edit.py)
    "NET-SSH-OPEN-001": "CIS 5.2 (pas d'accès SSH ouvert à Internet) / DORA Art. 9 (protection des données)",
}
UNSUPPORTED_REASON = (
    "aucune stratégie de correction IaC vérifiée pour cette règle dans ce SI (NET-001 : aucune ressource "
    "réseau Terraform gérée ; IAM-001 : identités Entra hors IaC ; CIS-003 : propriétaire inconnu, il "
    "faut une décision humaine ; CIS-011 : aucune ressource de rôle gérée ; IAM-STALE-ROLE-001 : "
    "désactiver un rôle sans vérifier ses dépendances ne serait pas déterministe ; CERT-EXPIRED-001 : "
    "le renouvellement se fait hors IaC (CA/ACM), aucun diff Terraform ne le corrige)"
)


def inline_code(value: str, limit: int = 200) -> str:
    """Valeur externe (nom d'actif, titre...) mise en code en ligne Markdown, sans pouvoir en sortir."""
    clean = " ".join(value.replace("`", "'").split())[:limit]
    return f"`{clean}`"


def code_fence(content: str) -> str:
    """Clôture Markdown plus longue que toute suite de ` dans le contenu : il ne peut pas la fermer."""
    longest = run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def branch_name(finding: Finding) -> str:
    """Stable : même finding (règle + actifs) => même branche, donc pas de doublon après un redémarrage."""
    rule_id, nodes = fingerprint(finding)
    digest = hashlib.sha256(f"{rule_id}|{','.join(nodes)}".encode()).hexdigest()[:10]
    return f"cuz/{rule_id.lower()}-{digest}"


class GitOpsPRGenerator:
    def __init__(
        self,
        gitea_base_url: str,
        admin_token: str,
        iac_repo: str,
        org: str = "acmecorp",
        transport: httpx.AsyncBaseTransport | None = None,
        audit: AuditHook | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base = f"{gitea_base_url.rstrip('/')}/api/v1/repos/{org}/{iac_repo}"
        self.web_base = gitea_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"token {admin_token}",
            "Content-Type": "application/json",
        }
        self._transport = transport
        self._timeout = timeout
        self._audit = audit
        self._jinja = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=False,
            undefined=StrictUndefined,
            keep_trailing_newline=True,
        )

    # ── Gitea ───────────────────────────────────────────────────────────────────────────

    async def _call(
        self,
        client: httpx.AsyncClient,
        step: str,
        method: str,
        path: str,
        ok: tuple[int, ...] = (200, 201),
        **kw: Any,
    ) -> httpx.Response:
        try:
            r = await client.request(method, f"{self.base}{path}", **kw)
        except httpx.HTTPError as exc:
            raise GitOpsError(step, None, f" ({type(exc).__name__})") from exc
        if r.status_code not in ok:
            raise GitOpsError(step, r.status_code, f" : {r.text[:200]}")
        return r

    async def _terraform_files(
        self, client: httpx.AsyncClient, branch: str
    ) -> dict[str, tuple[str, str]]:
        """{chemin: (texte, sha)} de tous les .tf de la branche par défaut."""
        tree = (
            await self._call(
                client, "arbre du dépôt", "GET", f"/git/trees/{branch}?recursive=true&per_page=1000"
            )
        ).json()
        paths = sorted(
            t["path"]
            for t in tree.get("tree", [])
            if t.get("type") == "blob" and t["path"].endswith(".tf")
        )
        if len(paths) > MAX_TF_FILES:
            raise RemediationNotApplicableError(
                f"dépôt IaC trop volumineux ({len(paths)} fichiers .tf)"
            )
        files: dict[str, tuple[str, str]] = {}
        for path in paths:
            data = (
                await self._call(
                    client, f"lecture de {path}", "GET", f"/contents/{path}?ref={branch}"
                )
            ).json()
            if data.get("size", 0) > MAX_TF_FILE_BYTES:
                continue
            files[path] = (
                base64.b64decode(data["content"]).decode("utf-8", errors="replace"),
                data["sha"],
            )
        return files

    async def _existing_pr(self, client: httpx.AsyncClient, branch: str) -> dict[str, Any] | None:
        for page in range(1, 6):
            r = await self._call(
                client, "liste des PR", "GET", f"/pulls?state=all&limit=50&page={page}"
            )
            prs = r.json()
            for pr in prs:
                if pr.get("head", {}).get("ref") == branch:
                    return pr  # type: ignore[no-any-return]
            if len(prs) < 50:
                return None
        return None

    # ── logique ─────────────────────────────────────────────────────────────────────────

    def _check_allowed(self, finding: Finding) -> None:
        if can_automate_finding(finding):
            return
        tier = classify(finding.rule_id)
        if int(tier) != 1:
            why = f"{finding.rule_id} est Tier {int(tier)}, seul le Tier 1 est automatisable"
        elif finding.status != "open":
            why = f"finding {finding.status}, seul un finding ouvert déclenche une PR"
        else:
            why = f"confiance {finding.confidence_score:.2f} < {MIN_CONFIDENCE_FOR_AUTOMATION} (RÈGLE 3)"
        raise PermissionError(f"PR refusée (RÈGLE 7) : {why}")

    def _locate_single(
        self,
        asset: str,
        files: dict[str, tuple[str, str]],
        locate: Callable[[str, str, frozenset[str]], list[Any]],
        resource_types: frozenset[str],
    ) -> tuple[str, str, Any]:
        """(chemin, texte, bloc) unique correspondant à `asset`, ou RemediationNotApplicableError
        si aucun ou plusieurs (ambigu) — factorisé entre tous les types de ressources P2.10/bis."""
        matches: list[tuple[str, str, Any]] = []
        for path, (text, _sha) in files.items():
            try:
                blocks = locate(text, asset, resource_types)
            except HCLError as exc:
                logger.warning("fichier %s non analysable, ignoré : %s", path, exc)
                continue
            matches.extend((path, text, b) for b in blocks)
        if not matches:
            raise RemediationNotApplicableError(
                "cet actif n'est pas géré par le dépôt IaC (aucune ressource ne le déclare) : "
                "une PR ne peut pas le corriger"
            )
        if len(matches) > 1:
            raise RemediationNotApplicableError(
                "l'actif est déclaré plusieurs fois dans le dépôt IaC (ambigu)"
            )
        return matches[0]

    def _plan_bucket(
        self, asset: str, files: dict[str, tuple[str, str]]
    ) -> tuple[str, TerraformEdit]:
        path, text, block = self._locate_single(asset, files, locate_bucket, BUCKET_RESOURCE_TYPES)
        try:
            return path, make_bucket_private(text, block)
        except AlreadyPrivateError as exc:
            raise RemediationNotApplicableError(
                "le code IaC est déjà privé : l'écart est côté infrastructure réelle (dérive), "
                "corriger par terraform apply et non par une PR"
            ) from exc
        except NonLiteralValueError as exc:
            raise RemediationNotApplicableError(
                "l'attribut acl n'est pas un littéral : modification non déterministe"
            ) from exc

    def _plan_security_group_rule(
        self, asset: str, files: dict[str, tuple[str, str]]
    ) -> tuple[str, TerraformEdit]:
        path, text, block = self._locate_single(
            asset, files, locate_security_group_rule, NSG_RESOURCE_TYPES
        )
        try:
            return path, close_open_cidr(text, block)
        except AlreadyClosedError as exc:
            raise RemediationNotApplicableError(
                "0.0.0.0/0 n'est déjà plus dans cidr_blocks : l'écart est côté infrastructure "
                "réelle (dérive), corriger par terraform apply et non par une PR"
            ) from exc
        except NonLiteralValueError as exc:
            raise RemediationNotApplicableError(
                "cidr_blocks n'est pas une liste de littéraux : modification non déterministe"
            ) from exc

    _PLANNERS: dict[str, str] = {
        "STORAGE-PUBLIC-001": "_plan_bucket",
        "NET-SSH-OPEN-001": "_plan_security_group_rule",
    }

    def _plan(
        self, finding: Finding, files: dict[str, tuple[str, str]]
    ) -> tuple[str, str, TerraformEdit]:
        """(asset, chemin, modification) ou RemediationNotApplicableError."""
        if finding.rule_id not in SUPPORTED_RULES:
            raise RemediationNotApplicableError(UNSUPPORTED_REASON)
        if len(finding.affected_node_names) != 1:
            raise RemediationNotApplicableError(
                "le finding vise plusieurs actifs : une PR par actif est requise"
            )
        asset = finding.affected_node_names[0]
        planner = getattr(self, self._PLANNERS[finding.rule_id])
        path, edit = planner(asset, files)
        return asset, path, edit

    def build_pr_body(self, finding: Finding, asset: str, path: str, diff: str, actor: str) -> str:
        return self._jinja.get_template("pr_body.md.j2").render(
            title=inline_code(finding.title),
            rule_id=f"`{finding.rule_id}`"
            if finding.rule_id in SUPPORTED_RULES
            else inline_code(finding.rule_id),
            severity=finding.severity,
            tier=int(classify(finding.rule_id)),
            confidence=round(finding.confidence_score * 100),
            asset=inline_code(asset),
            file_path=inline_code(path),
            justification=SUPPORTED_RULES.get(finding.rule_id, ""),
            finding_link=f"/api/v1/tenants/{finding.tenant_id}/findings/{finding.id}",
            diff=diff.rstrip("\n"),
            fence=code_fence(diff),
            actor=inline_code(actor),
        )

    async def _record(self, action: str, detail: str) -> None:
        if self._audit is not None:
            await self._audit(action, detail)

    async def generate_pr(self, finding: Finding, actor: str = "cuz") -> PullRequestResult:
        self._check_allowed(finding)
        branch = branch_name(finding)
        async with httpx.AsyncClient(
            headers=self._headers, timeout=self._timeout, transport=self._transport
        ) as client:
            repo = (await self._call(client, "dépôt", "GET", "")).json()
            default = repo["default_branch"]

            existing = await self._existing_pr(client, branch)
            if existing is not None:
                if existing.get("state") == "open":
                    return PullRequestResult(
                        existing["number"], existing["html_url"], branch, "", created=False
                    )
                state = "mergée" if existing.get("merged") else "fermée"
                raise RemediationNotApplicableError(
                    f"une PR existe déjà pour ce finding (#{existing['number']}, {state}) : "
                    "elle n'est pas rouverte automatiquement"
                )

            files = await self._terraform_files(client, default)
            asset, path, edit = self._plan(finding, files)
            diff = edit.diff(path)
            body = self.build_pr_body(finding, asset, path, diff, actor)

            await self._record(
                "gitops_pr_requested", f"{branch} {path}"
            )  # si l'audit échoue : rien n'est écrit
            branch_created = False
            try:
                await self._call(client, "création de la branche", "POST", "/branches",
                                 json={"new_branch_name": branch, "old_branch_name": default})  # fmt: skip
                branch_created = True
                await self._call(
                    client, "commit du correctif", "PUT", f"/contents/{path}",
                    json={
                        "branch": branch,
                        "sha": files[path][1],
                        "content": base64.b64encode(edit.after.encode()).decode(),
                        "message": f"fix({finding.rule_id}): {inline_code(asset)} privé",
                    },
                )  # fmt: skip
                r = await self._call(
                    client, "ouverture de la PR", "POST", "/pulls",
                    json={"title": f"[CUz] {finding.rule_id} : {asset}"[:200], "body": body, "head": branch, "base": default},
                )  # fmt: skip
            except Exception as exc:
                if branch_created:  # pas de branche orpheline : une retentative repart propre
                    try:
                        await self._call(
                            client,
                            "nettoyage de la branche",
                            "DELETE",
                            f"/branches/{branch}",
                            ok=(204,),
                        )
                    except GitOpsError:
                        logger.error(
                            "branche %s non supprimée après échec : à nettoyer à la main", branch
                        )
                await self._record("gitops_pr_failed", f"{branch} : {type(exc).__name__}")
                raise
            pr = r.json()
            await self._record("gitops_pr_opened", f"{pr['html_url']}")
            return PullRequestResult(pr["number"], pr["html_url"], branch, path, created=True)
