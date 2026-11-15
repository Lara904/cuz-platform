# packages/connectors/terraform/tests/test_terraform.py
import asyncio
import json
from pathlib import Path

import pytest

from packages.connectors.terraform.connector import DEFAULT_TFSTATE, TerraformConnector
from packages.connectors.terraform.mapper import TerraformMapper, load_resources
from packages.core.models.enums import NodeType
from packages.ingestion.normalizer import Normalizer

TENANT = "acmecorp"


def _state(tmp_path: Path, resources: list[dict]) -> Path:
    path = tmp_path / "state.tfstate"
    path.write_text(json.dumps({"version": 4, "resources": resources}), encoding="utf-8")
    return path


def test_pull_full_returns_one_event_per_instance():
    # 3 ressources P0 (frontend/backend/acmecorp-archive) + 3 fixtures P2.10 bis (DEC-004)
    conn = TerraformConnector(TENANT, {"path": DEFAULT_TFSTATE})
    events = asyncio.run(conn.pull_full())
    assert len(events) == 6
    assert all(e.source == "terraform" and e.tenant_id == TENANT for e in events)


def test_mapper_bucket_node_has_scores_and_iac_tag():
    res = {
        "type": "minio_bucket",
        "name": "acmecorp-archive",
        "attributes": {"bucket": "acmecorp-archive"},
    }
    node = TerraformMapper(TENANT).map_resource(res)
    assert node.node_type == NodeType.STORAGE
    assert node.name == "acmecorp-archive"
    assert node.tags["iac_managed"] == "true"
    assert node.confidence_score >= 0.7  # sous 0.7 → quarantaine
    assert 0.0 <= node.freshness_score <= 1.0


def test_mapper_ignores_unknown_resource_types():
    assert (
        TerraformMapper(TENANT).map_resource(
            {"type": "google_storage_bucket", "name": "x", "attributes": {}}
        )
        is None
    )


def test_load_resources_flattens_instances(tmp_path):
    path = _state(
        tmp_path,
        [
            {
                "type": "minio_bucket",
                "name": "b",
                "instances": [{"attributes": {"bucket": "b"}}, {"attributes": {"bucket": "b2"}}],
            }
        ],
    )
    assert len(load_resources(path)) == 2


def test_normalizer_produces_terraform_storage_node():
    conn = TerraformConnector(TENANT, {"path": DEFAULT_TFSTATE})
    raw = [
        e for e in asyncio.run(conn.pull_full()) if e.raw_data["resource"]["type"] == "minio_bucket"
    ][0]
    results = Normalizer().normalize(raw)
    assert len(results) == 1
    assert results[0].node.id == "terraform:minio_bucket.acmecorp-archive"


def test_test_connection_fails_on_missing_file(tmp_path):
    conn = TerraformConnector(TENANT, {"path": tmp_path / "absent.tfstate"})
    with pytest.raises(FileNotFoundError):
        asyncio.run(conn.test_connection())


def test_test_connection_ok_on_fixture():
    assert asyncio.run(TerraformConnector(TENANT, {"path": DEFAULT_TFSTATE}).test_connection())


# ── P2.3 : drift IaC et baseline ─────────────────────────────────────────────

from packages.connectors.terraform.mapper import compute_drift  # noqa: E402


def test_compute_drift_detects_acmecorp_archive():
    """AC.6 : acmecorp-archive est déclaré en IaC mais absent du réel."""
    iac = {"acmecorp-data", "acmecorp-logs", "acmecorp-public", "acmecorp-archive"}
    real = {"acmecorp-data", "acmecorp-logs", "acmecorp-public"}
    drift = compute_drift(iac, real)
    assert drift["resources_in_iac_but_missing_real"] == ["acmecorp-archive"]
    assert drift["drift_count"] == 0


def test_compute_drift_flags_unmanaged_real_resource():
    drift = compute_drift({"a"}, {"a", "b", "c", "d"})
    assert drift["resources_not_in_iac"] == ["b", "c", "d"]
    assert drift["drift_rate_pct"] == 75.0


def test_compute_drift_rate_is_none_without_real_resources():
    assert compute_drift({"a"}, set())["drift_rate_pct"] is None


def test_state_path_read_from_environment(monkeypatch, tmp_path):
    state = tmp_path / "custom.tfstate"
    state.write_text('{"version": 4, "resources": []}', encoding="utf-8")
    monkeypatch.setenv("TERRAFORM_STATE_PATH", str(state))
    assert TerraformConnector(TENANT, {}).path == state


def test_aws_and_azure_types_are_mapped():
    mapper = TerraformMapper(TENANT)
    assert (
        mapper.map_resource(
            {"type": "aws_s3_bucket", "name": "b", "attributes": {"bucket": "b"}}
        ).node_type
        == NodeType.STORAGE
    )
    assert (
        mapper.map_resource({"type": "aws_instance", "name": "i", "attributes": {}}).node_type
        == NodeType.SERVER
    )


# ── P2.10 bis (DEC-004) : rôle IAM, règle réseau, certificat ────────────────────────────


def test_stale_iam_role_is_mapped_to_role_with_unused_flag():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_iam_role",
            "name": "stale_admin_role",
            "attributes": {"name": "stale-admin-role", "last_used_date": "2026-05-01T00:00:00Z"},
        }
    )
    assert node.node_type == NodeType.ROLE
    assert node.name == "stale-admin-role"
    assert node.attributes["role_unused_90d"] is True
    assert node.attributes["role_unused_days"] > 90


def test_recently_used_iam_role_is_not_flagged_unused():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_iam_role",
            "name": "active_role",
            "attributes": {"name": "active-role", "last_used_date": "2026-11-01T00:00:00Z"},
        }
    )
    assert node.attributes["role_unused_90d"] is False


def test_ssh_open_security_group_rule_is_mapped_to_network_with_both_flags():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_security_group_rule",
            "name": "ssh_open_world",
            "attributes": {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"],
            },
        }
    )
    assert node.node_type == NodeType.NETWORK
    assert node.attributes["port_22_exposed"] is True
    assert node.attributes["is_public"] is True


def test_security_group_rule_restricted_to_a_private_cidr_is_not_flagged_public():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_security_group_rule",
            "name": "ssh_bastion_only",
            "attributes": {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"],
            },
        }
    )
    assert node.attributes["port_22_exposed"] is True
    assert node.attributes["is_public"] is False


def test_security_group_rule_for_another_port_is_not_flagged_ssh_exposed():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_security_group_rule",
            "name": "https_open",
            "attributes": {
                "from_port": 443,
                "to_port": 443,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"],
            },
        }
    )
    assert node.attributes["port_22_exposed"] is False


def test_expired_certificate_is_mapped_to_certificate_with_expired_flag():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_acm_certificate",
            "name": "expired_cert",
            "attributes": {
                "domain_name": "legacy.acmecorp.local",
                "not_after": "2026-01-01T00:00:00Z",
            },
        }
    )
    assert node.node_type == NodeType.CERTIFICATE
    assert node.name == "legacy.acmecorp.local"
    assert node.attributes["cert_expired"] is True


def test_valid_certificate_is_not_flagged_expired():
    node = TerraformMapper(TENANT).map_resource(
        {
            "type": "aws_acm_certificate",
            "name": "valid_cert",
            "attributes": {"domain_name": "acmecorp.local", "not_after": "2099-01-01T00:00:00Z"},
        }
    )
    assert node.attributes["cert_expired"] is False
