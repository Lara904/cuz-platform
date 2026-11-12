# packages/connectors/terraform/tests/test_baseline.py
from packages.connectors.terraform.baseline import build_keys
from packages.connectors.terraform.mapper import compute_drift


def _iac(node_type, name, ns="production"):
    return {
        "node_type": node_type,
        "name": name,
        "attrs": f'{{"namespace": "{ns}"}}',
        "owner_deployment": None,
        "freshness": 1.0,
    }


def _real(node_type, name, owner=None, fresh=1.0, ns="production"):
    return {
        "node_type": node_type,
        "name": name,
        "attrs": f'{{"namespace": "{ns}"}}',
        "owner_deployment": owner,
        "freshness": fresh,
    }


def test_frontend_and_backend_are_not_false_positives():
    iac, real = build_keys(
        [
            _iac("CONTAINER", "backend"),
            _iac("CONTAINER", "frontend"),
            _iac("STORAGE", "acmecorp-archive"),
        ],
        [
            _real("CONTAINER", "backend-655845b697-8sqbw", owner="backend"),
            _real("CONTAINER", "frontend-568f9867cd-24ff9", owner="frontend"),
            _real("STORAGE", "acmecorp-public"),
        ],
    )
    drift = compute_drift(iac, real)
    assert "DEPLOYMENT:production/backend" not in drift["resources_in_iac_but_missing_real"]
    assert "DEPLOYMENT:production/frontend" not in drift["resources_in_iac_but_missing_real"]
    assert drift["resources_in_iac_but_missing_real"] == ["STORAGE:acmecorp-archive"]


def test_stale_pods_do_not_count_as_real_deployment():
    iac, real = build_keys(
        [_iac("CONTAINER", "backend")],
        [_real("CONTAINER", "backend-old", owner="backend", fresh=0.1)],
    )
    assert (
        "DEPLOYMENT:production/backend"
        in compute_drift(iac, real)["resources_in_iac_but_missing_real"]
    )


def test_namespace_is_part_of_deployment_key():
    iac, real = build_keys(
        [_iac("CONTAINER", "backend", ns="production")],
        [_real("CONTAINER", "backend-x", owner="backend", ns="staging")],
    )
    assert (
        "DEPLOYMENT:production/backend"
        in compute_drift(iac, real)["resources_in_iac_but_missing_real"]
    )


def test_unmanaged_real_deployment_is_drift():
    iac, real = build_keys([], [_real("CONTAINER", "legacy-x", owner="legacy")])
    assert compute_drift(iac, real)["resources_not_in_iac"] == ["DEPLOYMENT:production/legacy"]
