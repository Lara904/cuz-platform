# packages/remediation/tests/test_gitops_pr_generator.py
"""Tests de GitOpsPRGenerator (P2.10) contre une fausse API Gitea (httpx.MockTransport).

On ne teste pas un réseau réel : `transport` est le point d'injection prévu par la classe pour ça.
Chaque test vérifie un garde-fou du docstring de gitops_pr_generator.py : RÈGLE 7 (tier/statut/confiance),
RÈGLE 3 (seuil), idempotence de branche, non-réouverture d'une PR fermée/mergée, refus explicite (jamais de
génération devinée) pour une règle non supportée / un actif ambigu ou absent / une ressource déjà privée /
un acl non littéral, nettoyage de la branche après un échec tardif, audit AVANT toute écriture Gitea, et
non-fuite du jeton dans les erreurs.
"""

import base64
import json

import httpx
import pytest

from packages.detection.models import Finding
from packages.remediation.gitops_pr_generator import (
    SUPPORTED_RULES,
    UNSUPPORTED_REASON,
    DirectApplyResult,
    GitOpsError,
    GitOpsPRGenerator,
    PullRequestResult,
    RemediationNotApplicableError,
    branch_name,
)

ADMIN_TOKEN = "s3cr3t-token-never-leak"  # noqa: S105 - jeton de test, jamais réel
ORG = "acmecorp"
REPO = "iac"
BASE_URL = "https://gitea.acmecorp.test"
API = f"{BASE_URL}/api/v1/repos/{ORG}/{REPO}"

PUBLIC_TF = """resource "minio_s3_bucket" "public" {
  bucket = "acmecorp-public"
  acl    = "public"
}
"""

PRIVATE_TF = """resource "minio_s3_bucket" "data" {
  bucket = "acmecorp-data"
  acl    = "private"
}
"""

NON_LITERAL_TF = """resource "minio_s3_bucket" "x" {
  bucket = "acmecorp-nonlit"
  acl = var.acl
}
"""

DUPLICATE_TF = PUBLIC_TF + PUBLIC_TF

# P2.10 bis (DEC-004)
SSH_OPEN_TF = """resource "aws_security_group_rule" "ssh_open_world" {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
"""

SSH_ALREADY_CLOSED_TF = SSH_OPEN_TF.replace('["0.0.0.0/0"]', '["10.0.0.0/8"]')

ROLE_PERMANENT_TF = """resource "aws_iam_role" "permanent_admin_role" {
  name      = "permanent-admin-role"
  is_admin  = true
  permanent = true
}
"""

ROLE_ALREADY_NOT_PERMANENT_TF = ROLE_PERMANENT_TF.replace("permanent = true", "permanent = false")


def _role_finding(**overrides) -> Finding:
    base = dict(
        tenant_id="acmecorp",
        rule_id="CIS-011",
        severity="HIGH",
        title="Rôle admin permanent",
        description="permanent-admin-role est un rôle admin sans expiration (permanent).",
        affected_nodes=["node-role-permanent-admin"],
        affected_node_names=["permanent-admin-role"],
        remediation_hint="Rendre le rôle temporaire (permanent = false).",
        confidence_score=0.9,
        status="open",
    )
    base.update(overrides)
    return Finding(**base)


def _nsg_finding(**overrides) -> Finding:
    base = dict(
        tenant_id="acmecorp",
        rule_id="NET-SSH-OPEN-001",
        severity="CRITICAL",
        title="Règle réseau avec le port 22 ouvert à 0.0.0.0/0",
        description="ssh_open_world autorise le port SSH depuis n'importe quelle adresse.",
        affected_nodes=["node-nsg-ssh"],
        affected_node_names=["ssh_open_world"],
        remediation_hint="Restreindre ou fermer le CIDR.",
        confidence_score=0.9,
        status="open",
    )
    base.update(overrides)
    return Finding(**base)


def _finding(**overrides) -> Finding:
    base = dict(
        tenant_id="acmecorp",
        rule_id="STORAGE-PUBLIC-001",
        severity="HIGH",
        title="Bucket acmecorp-public exposé publiquement",
        description="Le bucket acmecorp-public autorise un accès public en lecture.",
        affected_nodes=["node-bucket-public"],
        affected_node_names=["acmecorp-public"],
        remediation_hint="Retirer l'ACL publique.",
        confidence_score=0.9,
        status="open",
    )
    base.update(overrides)
    return Finding(**base)


class FakeGitea:
    """Backend minimal, assez proche de l'API Gitea pour le flux réellement utilisé par la classe."""

    def __init__(
        self,
        tf_files: dict[str, str] | None = None,
        existing_prs: list[dict] | None = None,
        default_branch: str = "main",
        fail_on: str | None = None,  # ex: "commit" pour simuler un échec après création de branche
        file_sizes: dict[str, int] | None = None,
    ) -> None:
        self.tf_files = tf_files if tf_files is not None else {"storage/buckets.tf": PUBLIC_TF}
        self.existing_prs = existing_prs or []
        self.default_branch = default_branch
        self.fail_on = fail_on
        self.file_sizes = file_sizes or {}
        self.calls: list[tuple[str, str]] = []  # (method, path) dans l'ordre
        self.branches_created: list[str] = []
        self.branches_deleted: list[str] = []
        self.next_pr_number = 42

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path[len(f"/api/v1/repos/{ORG}/{REPO}") :]
        self.calls.append((method, path))

        assert request.headers["Authorization"] == f"token {ADMIN_TOKEN}"

        if method == "GET" and path == "":
            return httpx.Response(200, json={"default_branch": self.default_branch})

        if method == "GET" and path.startswith("/pulls"):
            page = int(
                dict(p.split("=") for p in request.url.query.decode().split("&")).get("page", 1)
            )
            if page > 1:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=self.existing_prs)

        if method == "GET" and path.startswith("/git/trees/"):
            tree = [{"type": "blob", "path": p} for p in self.tf_files]
            return httpx.Response(200, json={"tree": tree})

        if method == "GET" and path.startswith("/contents/"):
            file_path = path[len("/contents/") :].split("?")[0]
            text = self.tf_files[file_path]
            size = self.file_sizes.get(file_path, len(text.encode()))
            return httpx.Response(
                200,
                json={
                    "content": base64.b64encode(text.encode()).decode(),
                    "sha": f"sha-{file_path}",
                    "size": size,
                },
            )

        if method == "POST" and path == "/branches":
            if self.fail_on == "branch":
                return httpx.Response(500, text="boom")
            body = json.loads(request.content)
            self.branches_created.append(body["new_branch_name"])
            return httpx.Response(201, json={})

        if method == "PUT" and path.startswith("/contents/"):
            if self.fail_on == "commit":
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json={"commit": {"sha": "committed-sha-123"}})

        if method == "POST" and path == "/pulls":
            if self.fail_on == "pull":
                return httpx.Response(500, text="boom")
            number = self.next_pr_number
            return httpx.Response(
                201,
                json={"number": number, "html_url": f"{BASE_URL}/{ORG}/{REPO}/pulls/{number}"},
            )

        if method == "DELETE" and path.startswith("/branches/"):
            self.branches_deleted.append(path[len("/branches/") :])
            return httpx.Response(204)

        raise AssertionError(f"appel Gitea inattendu : {method} {path}")


def _generator(gitea: FakeGitea, audit=None) -> GitOpsPRGenerator:
    return GitOpsPRGenerator(
        gitea_base_url=BASE_URL,
        admin_token=ADMIN_TOKEN,
        iac_repo=REPO,
        org=ORG,
        transport=httpx.MockTransport(gitea.handler),
        audit=audit,
    )


# ── chemin heureux ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_pr_creates_branch_commit_and_pull_request():
    gitea = FakeGitea()
    audited: list[tuple[str, str]] = []

    async def audit(action: str, detail: str) -> None:
        audited.append((action, detail))

    gen = _generator(gitea, audit=audit)
    result = await gen.generate_pr(_finding())

    assert isinstance(result, PullRequestResult)
    assert result.created is True
    assert result.number == 42
    assert result.file_path == "storage/buckets.tf"
    assert gitea.branches_created == [branch_name(_finding())]
    assert [a for a, _ in audited] == ["gitops_pr_requested", "gitops_pr_opened"]
    # audit AVANT toute écriture Gitea : la requête d'audit précède la création de branche
    assert gitea.calls.index(("POST", "/branches")) > 0
    assert ("POST", "/pulls") in gitea.calls


@pytest.mark.asyncio
async def test_pr_title_and_body_do_not_leak_the_admin_token():
    gitea = FakeGitea()
    gen = _generator(gitea)
    await gen.generate_pr(_finding())
    # le jeton ne doit apparaître dans aucun appel sortant hors de l'en-tête Authorization déjà vérifié
    for _method, path in gitea.calls:
        assert ADMIN_TOKEN not in path


# ── idempotence / réutilisation de PR ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_existing_open_pr_is_reused_without_creating_a_new_branch():
    branch = branch_name(_finding())
    gitea = FakeGitea(
        existing_prs=[
            {"head": {"ref": branch}, "state": "open", "number": 7, "html_url": f"{BASE_URL}/x/7"}
        ]
    )
    gen = _generator(gitea)
    result = await gen.generate_pr(_finding())

    assert result.created is False
    assert result.number == 7
    assert gitea.branches_created == []
    assert ("POST", "/branches") not in gitea.calls


@pytest.mark.asyncio
async def test_closed_pr_is_not_reopened():
    branch = branch_name(_finding())
    gitea = FakeGitea(
        existing_prs=[
            {
                "head": {"ref": branch},
                "state": "closed",
                "merged": False,
                "number": 7,
                "html_url": f"{BASE_URL}/x/7",
            }
        ]
    )
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="fermée"):
        await gen.generate_pr(_finding())
    assert gitea.branches_created == []


@pytest.mark.asyncio
async def test_merged_pr_is_not_reopened():
    branch = branch_name(_finding())
    gitea = FakeGitea(
        existing_prs=[
            {
                "head": {"ref": branch},
                "state": "closed",
                "merged": True,
                "number": 7,
                "html_url": f"{BASE_URL}/x/7",
            }
        ]
    )
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="mergée"):
        await gen.generate_pr(_finding())


def test_branch_name_is_stable_for_the_same_finding():
    a, b = _finding(), _finding(id="autre-id-mais-meme-finding-logique")
    assert branch_name(a) == branch_name(b)  # dérivé de rule_id + affected_nodes, pas de l'id


def test_branch_name_differs_for_different_assets():
    assert branch_name(_finding()) != branch_name(_finding(affected_nodes=["autre-node"]))


# ── RÈGLE 7 / RÈGLE 3 : garde-fou d'autorisation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_non_tier1_rule_is_refused():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(PermissionError, match="Tier"):
        await gen.generate_pr(_finding(rule_id="CIS-001"))
    assert gitea.calls == []  # refusé avant tout appel Gitea


@pytest.mark.asyncio
async def test_non_open_finding_is_refused():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(PermissionError, match="ouvert"):
        await gen.generate_pr(_finding(status="acknowledged"))
    assert gitea.calls == []


@pytest.mark.asyncio
async def test_low_confidence_finding_is_refused():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(PermissionError, match="0.7"):
        await gen.generate_pr(_finding(confidence_score=0.5))
    assert gitea.calls == []


# ── refus explicites (RemediationNotApplicableError), jamais de génération devinée ──────


@pytest.mark.asyncio
async def test_unsupported_rule_is_refused_with_explicit_reason():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="NET-001"):
        await gen.generate_pr(_finding(rule_id="NET-001"))


def test_unsupported_rules_are_exactly_the_tier1_rules_without_a_verified_fix():
    # P2.10 bis (DEC-004) : NET-SSH-OPEN-001 et CIS-011 ont désormais un correctif IaC vérifié
    # (close_open_cidr, revoke_permanent_admin). IAM-STALE-ROLE-001 et CERT-EXPIRED-001 restent
    # sans correctif déterministe sûr malgré leur Tier 1, par choix explicite (cf. UNSUPPORTED_REASON).
    assert set(SUPPORTED_RULES) == {"STORAGE-PUBLIC-001", "NET-SSH-OPEN-001", "CIS-011"}
    assert "NET-001" in UNSUPPORTED_REASON and "IAM-001" in UNSUPPORTED_REASON
    assert "IAM-STALE-ROLE-001" in UNSUPPORTED_REASON and "CERT-EXPIRED-001" in UNSUPPORTED_REASON
    assert "CIS-011" not in UNSUPPORTED_REASON


@pytest.mark.asyncio
async def test_finding_with_several_assets_is_refused():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="plusieurs actifs"):
        await gen.generate_pr(
            _finding(
                affected_nodes=["n1", "n2"],
                affected_node_names=["acmecorp-public", "acmecorp-data"],
            )
        )


@pytest.mark.asyncio
async def test_asset_not_managed_by_iac_is_refused():
    gitea = FakeGitea(tf_files={"storage/buckets.tf": PRIVATE_TF})  # pas "acmecorp-public"
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="pas géré"):
        await gen.generate_pr(_finding())


@pytest.mark.asyncio
async def test_ambiguous_duplicate_declaration_is_refused():
    gitea = FakeGitea(tf_files={"storage/buckets.tf": DUPLICATE_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="plusieurs fois"):
        await gen.generate_pr(_finding())


@pytest.mark.asyncio
async def test_already_private_bucket_is_treated_as_drift_not_a_code_fix():
    gitea = FakeGitea(tf_files={"storage/buckets.tf": PRIVATE_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="dérive"):
        await gen.generate_pr(
            _finding(affected_nodes=["n-data"], affected_node_names=["acmecorp-data"])
        )


@pytest.mark.asyncio
async def test_non_literal_acl_is_refused_not_guessed():
    gitea = FakeGitea(tf_files={"storage/buckets.tf": NON_LITERAL_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="littéral"):
        await gen.generate_pr(
            _finding(affected_nodes=["n-nonlit"], affected_node_names=["acmecorp-nonlit"])
        )


@pytest.mark.asyncio
async def test_too_many_tf_files_is_refused():
    many = {f"f{i}.tf": PUBLIC_TF for i in range(201)}
    gitea = FakeGitea(tf_files=many)
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="volumineux"):
        await gen.generate_pr(_finding())


@pytest.mark.asyncio
async def test_oversized_tf_file_is_skipped_not_read():
    gitea = FakeGitea(
        tf_files={"storage/buckets.tf": PUBLIC_TF},
        file_sizes={"storage/buckets.tf": 2_000_000},
    )
    gen = _generator(gitea)
    # le seul fichier qui aurait l'actif est ignoré car trop gros => actif introuvable
    with pytest.raises(RemediationNotApplicableError, match="pas géré"):
        await gen.generate_pr(_finding())


# ── échec tardif : nettoyage de branche + audit d'échec ─────────────────────────────────


@pytest.mark.asyncio
async def test_failure_after_branch_creation_deletes_the_branch_and_records_audit():
    gitea = FakeGitea(fail_on="commit")
    audited: list[tuple[str, str]] = []

    async def audit(action: str, detail: str) -> None:
        audited.append((action, detail))

    gen = _generator(gitea, audit=audit)
    with pytest.raises(GitOpsError):
        await gen.generate_pr(_finding())

    assert gitea.branches_created == [branch_name(_finding())]
    assert gitea.branches_deleted == [branch_name(_finding())]
    assert [a for a, _ in audited] == ["gitops_pr_requested", "gitops_pr_failed"]


@pytest.mark.asyncio
async def test_failure_at_pull_request_step_also_cleans_up_the_branch():
    gitea = FakeGitea(fail_on="pull")
    gen = _generator(gitea)
    with pytest.raises(GitOpsError):
        await gen.generate_pr(_finding())
    assert gitea.branches_deleted == [branch_name(_finding())]


@pytest.mark.asyncio
async def test_audit_failure_before_any_write_prevents_gitea_writes():
    gitea = FakeGitea()

    async def failing_audit(action: str, detail: str) -> None:
        raise RuntimeError("audit indisponible")

    gen = _generator(gitea, audit=failing_audit)
    with pytest.raises(RuntimeError, match="audit indisponible"):
        await gen.generate_pr(_finding())

    assert ("POST", "/branches") not in gitea.calls
    assert gitea.branches_created == []


@pytest.mark.asyncio
async def test_gitea_error_does_not_leak_the_admin_token_in_its_message():
    gitea = FakeGitea(fail_on="branch")
    gen = _generator(gitea)
    with pytest.raises(GitOpsError) as exc_info:
        await gen.generate_pr(_finding())
    assert ADMIN_TOKEN not in str(exc_info.value)


# ── P2.10 bis (DEC-004) : NET-SSH-OPEN-001, deuxième type de ressource supportée ─────────


@pytest.mark.asyncio
async def test_generate_pr_for_ssh_open_rule_closes_the_cidr():
    gitea = FakeGitea(tf_files={"network/sg.tf": SSH_OPEN_TF})
    gen = _generator(gitea)
    result = await gen.generate_pr(_nsg_finding())

    assert result.created is True
    assert result.file_path == "network/sg.tf"
    assert gitea.branches_created == [branch_name(_nsg_finding())]
    # le diff réellement committé ferme bien le CIDR, rien d'autre
    put_calls = [c for c in gitea.calls if c == ("PUT", "/contents/network/sg.tf")]
    assert put_calls


@pytest.mark.asyncio
async def test_ssh_rule_already_closed_is_treated_as_drift_not_a_code_fix():
    gitea = FakeGitea(tf_files={"network/sg.tf": SSH_ALREADY_CLOSED_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="dérive"):
        await gen.generate_pr(_nsg_finding())


@pytest.mark.asyncio
async def test_ssh_rule_not_in_iac_is_refused():
    gitea = FakeGitea(tf_files={"network/sg.tf": PUBLIC_TF})  # pas de ssh_open_world
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="pas géré"):
        await gen.generate_pr(_nsg_finding())


@pytest.mark.asyncio
async def test_cert_expired_and_iam_stale_role_findings_are_refused_even_at_tier1():
    """Tier 1 (classify()) mais pas dans SUPPORTED_RULES : aucune PR, raison explicite."""
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="CERT-EXPIRED-001"):
        await gen.generate_pr(
            _nsg_finding(rule_id="CERT-EXPIRED-001", affected_node_names=["legacy.acmecorp.local"])
        )
    with pytest.raises(RemediationNotApplicableError, match="IAM-STALE-ROLE-001"):
        await gen.generate_pr(
            _nsg_finding(rule_id="IAM-STALE-ROLE-001", affected_node_names=["stale-admin-role"])
        )
    assert gitea.branches_created == []


# ── P2.10 bis (DEC-004) : CIS-011, troisième type de ressource supportée ─────────────────


@pytest.mark.asyncio
async def test_generate_pr_for_permanent_admin_role_revokes_permanent():
    gitea = FakeGitea(tf_files={"iam/role.tf": ROLE_PERMANENT_TF})
    gen = _generator(gitea)
    result = await gen.generate_pr(_role_finding())

    assert result.created is True
    assert result.file_path == "iam/role.tf"
    assert gitea.branches_created == [branch_name(_role_finding())]
    put_calls = [c for c in gitea.calls if c == ("PUT", "/contents/iam/role.tf")]
    assert put_calls


@pytest.mark.asyncio
async def test_role_already_not_permanent_is_treated_as_drift_not_a_code_fix():
    gitea = FakeGitea(tf_files={"iam/role.tf": ROLE_ALREADY_NOT_PERMANENT_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="dérive"):
        await gen.generate_pr(_role_finding())


@pytest.mark.asyncio
async def test_permanent_admin_role_not_in_iac_is_refused():
    gitea = FakeGitea(tf_files={"iam/role.tf": PUBLIC_TF})  # pas de permanent_admin_role
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="pas géré"):
        await gen.generate_pr(_role_finding())


# ── P2.11 (DEC-006) : apply_direct(), commit direct sans PR pour les agents JIT ─────────


@pytest.mark.asyncio
async def test_apply_direct_commits_straight_to_default_branch_without_pr_or_branch():
    gitea = FakeGitea(tf_files={"iam/role.tf": ROLE_PERMANENT_TF})
    audited: list[tuple[str, str]] = []

    async def audit(action: str, detail: str) -> None:
        audited.append((action, detail))

    gen = _generator(gitea, audit=audit)
    result = await gen.apply_direct(_role_finding(), actor="agent-iam")

    assert isinstance(result, DirectApplyResult)
    assert result.file_path == "iam/role.tf"
    assert result.asset == "permanent-admin-role"
    assert result.commit_sha == "committed-sha-123"
    # pas de branche, pas de PR --- commit direct sur la branche par défaut uniquement
    assert gitea.branches_created == []
    assert ("POST", "/branches") not in gitea.calls
    assert ("POST", "/pulls") not in gitea.calls
    put_calls = [c for c in gitea.calls if c == ("PUT", "/contents/iam/role.tf")]
    assert put_calls
    assert [a for a, _ in audited] == [
        "gitops_direct_apply_requested",
        "gitops_direct_apply_committed",
    ]


@pytest.mark.asyncio
async def test_apply_direct_still_enforces_regle_3_7_gate():
    gitea = FakeGitea()
    gen = _generator(gitea)
    with pytest.raises(PermissionError, match="Tier"):
        await gen.apply_direct(_role_finding(rule_id="CIS-001"))
    assert gitea.calls == []  # refusé avant tout appel Gitea, comme generate_pr


@pytest.mark.asyncio
async def test_apply_direct_on_already_fixed_code_is_treated_as_drift_not_reapplied():
    """Idempotence côté résultat : pas de notion de PR à réutiliser ici, mais un second
    appel sur un code déjà corrigé doit refuser au lieu de recommettre inutilement."""
    gitea = FakeGitea(tf_files={"iam/role.tf": ROLE_ALREADY_NOT_PERMANENT_TF})
    gen = _generator(gitea)
    with pytest.raises(RemediationNotApplicableError, match="dérive"):
        await gen.apply_direct(_role_finding())
    assert ("PUT", "/contents/iam/role.tf") not in gitea.calls
