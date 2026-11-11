# packages/entity_resolution/tests/test_probabilistic_resolver.py
import random
from datetime import UTC, datetime

import pandas as pd
import pytest

from packages.core.models.enums import NodeType
from packages.core.models.node import CuzNode
from packages.entity_resolution.probabilistic_resolver import (
    ProbabilisticResolver,
    compute_stats,
    measure_duplicate_rate,
    nodes_to_dataframe,
    normalize_name,
)
from packages.entity_resolution.splink_settings import prior_match_probability

WORDS = ["payroll", "billing", "ledger", "invoice", "treasury", "audit", "orders", "catalog",
         "shipping", "pricing", "loyalty", "refund", "tax", "reporting", "scheduler", "gateway"]


def synthetic_graph(seed: int = 7) -> tuple[pd.DataFrame, dict[str, set[frozenset]]]:
    """Graphe synthétique avec doublons connus (vérité terrain), répartis en trois familles :
    - both : même IP ET même nom (à la casse et aux séparateurs près) ;
    - ip : même IP, nom d'une autre convention de nommage (suffixe de domaine) ;
    - distinctive : pas d'IP, nom distinctif avec variante de casse/séparateur ;
    - uniform : pas d'IP, nom d'un schéma uniforme (srv-prod-NNN) : le nom ne discrimine pas."""
    rnd = random.Random(seed)
    rows: list[dict] = []
    truth: dict[str, set[frozenset]] = {"both": set(), "ip": set(), "distinctive": set(), "uniform": set()}

    def add(uid, node_type, name, ip, source):
        rows.append({"unique_id": uid, "node_type": node_type, "name": normalize_name(name),
                     "ip_address": ip, "source": source})

    for i in range(200):
        add(f"sn:{i}", "SERVER", f"srv-prod-{i:03d}", f"10.0.{i // 250}.{i % 250 + 1}", "servicenow")
    for k, i in enumerate(rnd.sample(range(200), 36)):
        kind = ("both", "ip", "uniform")[k // 12]
        ip = f"10.0.{i // 250}.{i % 250 + 1}" if kind in ("both", "ip") else None
        name = f"SRV_PROD_{i:03d}" if kind == "both" else f"SRV_PROD_{i:03d}.acme.local"
        add(f"az:{i}", "SERVER", name, ip, "azure")
        truth[kind].add(frozenset((f"sn:{i}", f"az:{i}")))
    for k in range(10):
        distinctive = f"{WORDS[k]}-{WORDS[k + 6]}"
        add(f"sn:app{k}", "APPLICATION", distinctive, None, "servicenow")
        add(f"gt:app{k}", "APPLICATION", distinctive.replace("-", "_").upper(), None, "gitea")
        truth["distinctive"].add(frozenset((f"sn:app{k}", f"gt:app{k}")))
    for i in range(30):
        add(f"k8s:{i}", "SERVER", f"node-worker-{i:02d}", f"172.16.0.{i + 1}", "kubernetes")
    return pd.DataFrame(rows), truth


@pytest.fixture(scope="module")
def trained() -> tuple[ProbabilisticResolver, pd.DataFrame, dict, dict]:
    df, truth = synthetic_graph()
    resolver = ProbabilisticResolver("synthetic")
    resolver.train(df)
    classified = resolver.classify(resolver.predict_candidate_pairs(df))

    def pairs(frame: pd.DataFrame) -> set[frozenset]:
        return {frozenset(p) for p in zip(frame["unique_id_l"], frame["unique_id_r"], strict=True)}

    return resolver, df, truth, {k: pairs(v) for k, v in classified.items()}


def test_measure_duplicate_rate():
    assert measure_duplicate_rate(total_nodes=1000, duplicate_pairs=15) == 1.5
    assert measure_duplicate_rate(total_nodes=0, duplicate_pairs=3) == 0.0


def test_classify_splits_by_threshold():
    df = pd.DataFrame({"unique_id_l": ["a", "b", "c"], "unique_id_r": ["a2", "b2", "c2"],
                       "match_probability": [0.95, 0.75, 0.30]})
    result = ProbabilisticResolver.classify(df)
    assert len(result["auto_merge"]) == 1
    assert len(result["needs_human_review"]) == 1
    assert len(result["rejected"]) == 1


def test_prior_probability_is_bounded_and_decreases_with_size():
    assert 0 < prior_match_probability(1, 0) < 1
    assert prior_match_probability(1000, 20_000) < prior_match_probability(100, 200) <= 0.5


def test_training_report_states_prior_is_assumed(trained):
    resolver = trained[0]
    assert resolver.training_report["prior_probability"].startswith("assumed")
    assert resolver.training_report["u_probabilities"] == "ok"
    assert resolver.training_report["m_probabilities"].startswith("specified")


def test_two_independent_evidences_are_auto_merged(trained):
    """IP identique ET nom identique : deux preuves indépendantes, fusion automatique."""
    _, _, truth, found = trained
    assert truth["both"] <= found["auto_merge"]


def test_single_evidence_duplicates_are_never_auto_merged(trained):
    """Une seule preuve (IP seule, ou nom distinctif seul) : jamais de fusion automatique.
    Limite connue : avec les priors actuels ces paires restent sous le seuil de revue (0.6)."""
    _, _, truth, found = trained
    assert not ((truth["ip"] | truth["distinctive"]) & found["auto_merge"])


def test_terraform_nodes_are_never_candidates():
    df, _ = synthetic_graph()
    df.loc[df["source"] == "azure", "source"] = "terraform"  # IaC vs réel : doivent rester distincts
    resolver = ProbabilisticResolver("synthetic")
    resolver.train(df)
    assert resolver.predict_candidate_pairs(df).empty


def test_no_false_positive_auto_merge(trained):
    _, _, truth, found = trained
    all_true = set().union(*truth.values())
    assert not (found["auto_merge"] - all_true)


def test_uniform_name_duplicates_are_a_known_blind_spot(trained):
    """Limite documentée : quand tous les noms suivent le même schéma, le nom seul ne distingue
    pas un doublon d'un voisin. Ces doublons ne sont PAS fusionnés automatiquement."""
    _, _, truth, found = trained
    assert not (truth["uniform"] & found["auto_merge"])


def test_same_source_nodes_are_never_candidates(trained):
    resolver, df, _, _ = trained
    source = df.set_index("unique_id")["source"]
    predictions = resolver.predict_candidate_pairs(df)
    assert (predictions["unique_id_l"].map(source) != predictions["unique_id_r"].map(source)).all()


def test_model_roundtrip_without_retraining(trained, tmp_path):
    resolver, df, _, found = trained
    path = resolver.save_model(tmp_path / "model.json")
    reloaded = ProbabilisticResolver("synthetic")
    reloaded.load_model(df, path)
    again = reloaded.classify(reloaded.predict_candidate_pairs(df))
    assert {frozenset(p) for p in zip(again["auto_merge"]["unique_id_l"],
                                      again["auto_merge"]["unique_id_r"], strict=True)} == found["auto_merge"]


def test_compute_stats_shape(trained):
    resolver, df, _, found = trained
    stats = compute_stats("synthetic", df, resolver)
    assert stats["total_nodes"] == len(df)
    assert stats["auto_merge_pairs"] == len(found["auto_merge"])
    assert stats["duplicate_rate_basis"] == "estimated_from_model"


def test_nodes_to_dataframe_uses_first_source_and_ip():
    node = CuzNode(tenant_id="t", node_type=NodeType.SERVER, name=" SRV-01 ", confidence_score=0.9,
                   freshness_score=1.0, sources=["servicenow", "azure"], last_seen=datetime.now(UTC),
                   attributes={"ip_address": "10.0.0.1"})
    row = nodes_to_dataframe([node]).iloc[0]
    assert (row["name"], row["ip_address"], row["source"]) == ("srv01", "10.0.0.1", "servicenow")
