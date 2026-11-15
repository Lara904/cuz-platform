import json

# Ressources managées par Terraform (certaines absentes du vrai k3d = drift volontaire)
resources = [
    {
        "type": "kubernetes_deployment",
        "name": "frontend",
        "provider": "kubernetes",
        "instances": [{"attributes": {"namespace": "production"}}],
    },
    {
        "type": "kubernetes_deployment",
        "name": "backend",
        "provider": "kubernetes",
        "instances": [{"attributes": {"namespace": "production"}}],
    },
    # Ressource NON présente dans k3d → drift volontaire
    {
        "type": "minio_bucket",
        "name": "acmecorp-archive",
        "provider": "minio",
        "instances": [{"attributes": {"bucket": "acmecorp-archive"}}],
    },
    # P2.10 bis (DEC-004) : fixtures fictives, 3 types Tier 1 sans équivalent réel sur AcmeCorp
    # (100% local, sans AWS ni Azure réels). Aucune ressource cloud créée, zéro coût.
    {
        "type": "aws_iam_role",
        "name": "stale_admin_role",
        "provider": "aws",
        "instances": [
            {
                "attributes": {
                    "name": "stale-admin-role",
                    "last_used_date": "2026-05-01T00:00:00Z",
                }
            }
        ],
    },
    {
        "type": "aws_security_group_rule",
        "name": "ssh_open_world",
        "provider": "aws",
        "instances": [
            {
                "attributes": {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            }
        ],
    },
    {
        "type": "aws_acm_certificate",
        "name": "expired_cert",
        "provider": "aws",
        "instances": [
            {
                "attributes": {
                    "domain_name": "legacy.acmecorp.local",
                    "not_after": "2026-01-01T00:00:00Z",
                }
            }
        ],
    },
    # CIS-011 (DEC-004) : rôle admin "permanent" — 4e ressource Tier 1, avec cette fois un
    # correctif IaC déterministe réel (permanent = true -> false), contrairement à
    # stale_admin_role et expired_cert ci-dessus qui restent volontairement sans PR possible.
    {
        "type": "aws_iam_role",
        "name": "permanent_admin_role",
        "provider": "aws",
        "instances": [
            {
                "attributes": {
                    "name": "permanent-admin-role",
                    "is_admin": True,
                    "permanent": True,
                }
            }
        ],
    },
]

tfstate = {"version": 4, "terraform_version": "1.7.0", "resources": resources}

with open("tests/fixtures/acmecorp.tfstate", "w") as f:
    json.dump(tfstate, f, indent=2)

print("acmecorp.tfstate généré")
