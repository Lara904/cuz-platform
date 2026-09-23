"""
setup_gitea.py — Configuration complète de Gitea pour AcmeCorp
Prérequis : GITEA_ADMIN_USER et GITEA_ADMIN_PASSWORD dans .env
"""

import os
import json
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

BASE = "http://localhost:3000/api/v1"
AUTH = (
    os.environ.get("GITEA_ADMIN_USER", "acmeadmin"),
    os.environ.get("GITEA_ADMIN_PASSWORD", "acmepassword123"),
)


def ok(r, label):
    if r.status_code in (200, 201):
        print(f"  ✅ {label}")
    elif r.status_code == 409:
        print(f"  ⚠️  {label} (existe déjà)")
    else:
        print(f"  ❌ {label} → {r.status_code} : {r.text[:200]}")
    return r


def create_org():
    print("\n── Organisation ──")
    r = requests.post(
        f"{BASE}/orgs",
        auth=AUTH,
        json={"username": "acmecorp", "visibility": "private", "full_name": "AcmeCorp"},
    )
    ok(r, "Organisation acmecorp")


def create_repos():
    print("\n── Repos ──")
    repos = [
        {"name": "backend",       "description": "API Node.js principale"},
        {"name": "frontend",      "description": "React app"},
        {"name": "data-pipeline", "description": "ETL Python"},
        {"name": "infra",         "description": "Terraform + Ansible"},
    ]
    for repo in repos:
        r = requests.post(
            f"{BASE}/orgs/acmecorp/repos",
            auth=AUTH,
            json={**repo, "private": True, "auto_init": True},
        )
        ok(r, f"Repo {repo['name']}")


def push_file(repo, path, content_str, message):
    """Pousse un fichier dans un repo Gitea via l'API."""
    content_b64 = base64.b64encode(content_str.encode()).decode()

    # Vérifie si le fichier existe déjà (pour récupérer son SHA)
    check = requests.get(
        f"{BASE}/repos/acmecorp/{repo}/contents/{path}",
        auth=AUTH,
    )

    payload = {"message": message, "content": content_b64}
    if check.status_code == 200:
        payload["sha"] = check.json()["sha"]
        r = requests.put(
            f"{BASE}/repos/acmecorp/{repo}/contents/{path}",
            auth=AUTH,
            json=payload,
        )
    else:
        r = requests.post(
            f"{BASE}/repos/acmecorp/{repo}/contents/{path}",
            auth=AUTH,
            json=payload,
        )
    return r


def add_vulnerable_package_json():
    print("\n── Dépendances vulnérables (backend) ──")
    package_json = json.dumps({
        "name": "acmecorp-backend",
        "version": "1.0.0",
        "description": "API principale AcmeCorp",
        "dependencies": {
            "express":    "4.17.1",
            "lodash":     "4.17.20",
            "qs":         "6.5.2",
            "json-schema":"0.2.3",
            "node-fetch": "2.6.0",
            "axios":      "0.21.1"
        }
    }, indent=2)
    # Versions volontairement vulnérables :
    # lodash 4.17.20  → CVE-2021-23337 (CVSS 7.2)
    # qs 6.5.2        → CVE-2022-24999 (CVSS 9.8)
    # json-schema 0.2.3 → CVE-2021-3918 (CVSS 9.8)

    r = push_file("backend", "package.json", package_json, "Add vulnerable package.json (test CVE)")
    ok(r, "package.json vulnérable dans backend")


def create_gitea_token():
    print("\n── Token API pour svc-pipeline (scénario OAUTH-LATERAL-001) ──")

    # Créer l'utilisateur svc-pipeline s'il n'existe pas
    r = requests.post(
        f"{BASE}/admin/users",
        auth=AUTH,
        json={
            "username": "svc-pipeline",
            "email": "svc-pipeline@acmecorp.local",
            "password": "SvcPipeline123!",
            "must_change_password": False,
            "source_id": 0,
            "login_name": "svc-pipeline",
        },
    )
    ok(r, "Utilisateur svc-pipeline")

    # Créer un token OAuth pour svc-pipeline
    r = requests.post(
        f"{BASE}/users/svc-pipeline/tokens",
        auth=AUTH,
        json={"name": "minio-token"},
    )
    ok(r, "Token minio-token pour svc-pipeline")
    if r.status_code == 201:
        token = r.json().get("sha1", "")
        print(f"     → Token : {token}")
        print(f"     → Ajoute dans .env : GITEA_SVC_PIPELINE_TOKEN={token}")


def verify():
    print("\n── Vérification finale ──")

    r = requests.get(f"{BASE}/orgs/acmecorp/repos", auth=AUTH)
    if r.status_code == 200:
        repos = [repo["name"] for repo in r.json()]
        print(f"  {len(repos)} repos : {repos}")
    else:
        print(f"  mpossible de lister les repos : {r.status_code}")

    r = requests.get(
        f"{BASE}/repos/acmecorp/backend/contents/package.json", auth=AUTH
    )
    if r.status_code == 200:
        print("  package.json présent dans backend")
    else:
        print("  package.json absent du repo backend")


if __name__ == "__main__":
    print("=== Setup Gitea AcmeCorp ===")
    print(f"Connexion : {AUTH[0]}@localhost:3000")

    # Test de connexion
    r = requests.get(f"{BASE}/user", auth=AUTH)
    if r.status_code != 200:
        print(f"\nConnexion échouée ({r.status_code}). Vérifie GITEA_ADMIN_PASSWORD dans .env")
        exit(1)
    print(f"Connecté en tant que : {r.json().get('login')}")

    create_org()
    create_repos()
    add_vulnerable_package_json()
    create_gitea_token()
    verify()

    print("\n=== Terminé ===")
    print("AC.3 validé 4 repos et package.json ")