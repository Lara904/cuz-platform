import json

# Ressources managées par Terraform (certaines absentes du vrai k3d = drift volontaire)
resources = [
    {"type": "kubernetes_deployment", "name": "frontend",
     "provider": "kubernetes", "instances": [{"attributes": {"namespace": "production"}}]},
    {"type": "kubernetes_deployment", "name": "backend",
     "provider": "kubernetes", "instances": [{"attributes": {"namespace": "production"}}]},
    # Ressource NON présente dans k3d → drift volontaire
    {"type": "minio_bucket", "name": "acmecorp-archive",
     "provider": "minio", "instances": [{"attributes": {"bucket": "acmecorp-archive"}}]},
]

tfstate = {
    "version": 4, "terraform_version": "1.7.0",
    "resources": resources
}

with open("tests/fixtures/acmecorp.tfstate", "w") as f:
    json.dump(tfstate, f, indent=2)

print("acmecorp.tfstate généré")