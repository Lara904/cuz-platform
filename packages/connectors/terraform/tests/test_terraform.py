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
    conn = TerraformConnector(TENANT, {"path": DEFAULT_TFSTATE})
    events = asyncio.run(conn.pull_full())
    assert len(events) == 3
    assert all(e.source == "terraform" and e.tenant_id == TENANT for e in events)


def test_mapper_bucket_node_has_scores_and_iac_tag():
    res = {"type": "minio_bucket", "name": "acmecorp-archive",
           "attributes": {"bucket": "acmecorp-archive"}}
    node = TerraformMapper(TENANT).map_resource(res)
    assert node.node_type == NodeType.STORAGE
    assert node.name == "acmecorp-archive"
    assert node.tags["iac_managed"] == "true"
    assert node.confidence_score >= 0.7  # sous 0.7 → quarantaine
    assert 0.0 <= node.freshness_score <= 1.0


def test_mapper_ignores_unknown_resource_types():
    assert TerraformMapper(TENANT).map_resource({"type": "google_storage_bucket", "name": "x",
                                                  "attributes": {}}) is None


def test_load_resources_flattens_instances(tmp_path):
    path = _state(tmp_path, [{"type": "minio_bucket", "name": "b", "instances": [
        {"attributes": {"bucket": "b"}}, {"attributes": {"bucket": "b2"}}]}])
    assert len(load_resources(path)) == 2


def test_normalizer_produces_terraform_storage_node():
    conn = TerraformConnector(TENANT, {"path": DEFAULT_TFSTATE})
    raw = [e for e in asyncio.run(conn.pull_full())
           if e.raw_data["resource"]["type"] == "minio_bucket"][0]
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
    assert mapper.map_resource({"type": "aws_s3_bucket", "name": "b",
                                "attributes": {"bucket": "b"}}).node_type == NodeType.STORAGE
    assert mapper.map_resource({"type": "aws_instance", "name": "i",
                                "attributes": {}}).node_type == NodeType.SERVER
