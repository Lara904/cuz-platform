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
    assert TerraformMapper(TENANT).map_resource({"type": "aws_s3_bucket", "name": "x",
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
