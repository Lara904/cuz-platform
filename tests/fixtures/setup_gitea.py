import requests, json

BASE = "http://localhost:3000/api/v1"
AUTH = ("acmeadmin", "Acmeadmin123")

repos = [
    {"name": "backend",     "description": "API Node.js principale"},
    {"name": "frontend",    "description": "React app"},
    {"name": "data-pipeline","description": "ETL Python"},
    {"name": "infra",       "description": "Terraform + Ansible"},
]

for repo in repos:
    r = requests.post(f"{BASE}/orgs/acmecorp/repos",
        auth=AUTH, json={**repo, "private": True, "auto_init": True})
    print(f"Repo {repo['name']} : {r.status_code}")