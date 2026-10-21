# packages/detection/tests/test_dedup.py
from packages.detection.dedup import deduplicate, fingerprint
from packages.detection.models import Finding


def _f(rule_id: str, nodes: list[str], confidence: float) -> Finding:
    return Finding(tenant_id="acmecorp", rule_id=rule_id, severity="HIGH", title="t",
                   description="d", affected_nodes=nodes,
                   affected_node_names=nodes, remediation_hint="h",
                   confidence_score=confidence)


def test_same_rule_same_nodes_keeps_highest_confidence():
    low = _f("IAM-001", ["u1"], 0.8)
    high = _f("IAM-001", ["u1"], 0.95)
    assert deduplicate([low, high]) == [high]


def test_node_order_does_not_matter_for_key():
    a = _f("ATTACK-PATH-001-PARTIAL", ["u", "r", "d"], 0.9)
    b = _f("ATTACK-PATH-001-PARTIAL", ["d", "u", "r"], 0.7)
    assert fingerprint(a) == fingerprint(b)
    assert deduplicate([b, a]) == [a]


def test_different_rule_same_nodes_are_kept():
    """Clé composite stricte : deux règles différentes ne se fusionnent pas."""
    assert len(deduplicate([_f("IAM-001", ["u1"], 0.9), _f("IAM-OPA-001", ["u1"], 0.9)])) == 2


def test_same_rule_different_nodes_are_kept():
    assert len(deduplicate([_f("IAM-001", ["u1"], 0.9), _f("IAM-001", ["u2"], 0.9)])) == 2


def test_tie_keeps_first_seen():
    first = _f("IAM-001", ["u1"], 0.9)
    second = _f("IAM-001", ["u1"], 0.9)
    assert deduplicate([first, second]) == [first]
