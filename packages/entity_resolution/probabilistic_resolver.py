# packages/entity_resolution/probabilistic_resolver.py
"""Resolver probabiliste Splink, en complément (pas en remplacement) du DeterministicResolver
de P1.6 : le déterministe matche d'abord sur identifiants forts (0 faux positif) ; Splink rattrape
les doublons que ces identifiants ne voient pas (même ressource sous deux noms proches vus par deux
connecteurs sans external_id commun).

Périmètre des candidats : paires de MÊME type et de sources DIFFÉRENTES (deux nœuds de la même
source ont des identifiants distincts : entités distinctes), hors source terraform (IaC ≠ réel).

Limites connues : un doublon ne présentant qu'UNE preuve (IP seule, ou nom seul) n'est jamais fusionné
automatiquement ; avec les priors actuels il reste sous le seuil de revue (0.6) et n'est donc pas
détecté. Un doublon dont le seul indice est un nom d'une autre convention de nommage (suffixe de
domaine, schéma uniforme) n'est pas vu non plus. Le recalibrage se fera sur les étiquettes de P2.6.

Seuls les u sont estimés sur le graphe. Le prior et les m sont spécifiés (le graphe ne contient
aucune paire fusionnée par P1.6 comme vérité terrain, et l'EM non supervisé y est dégénéré) ; les m
seront ré-estimés sur les étiquettes de la validation humaine (P2.6).

Usage : python -m packages.entity_resolution.probabilistic_resolver --tenant acmecorp [--train]
"""

import argparse
import asyncio
import json
import logging
import re
import shutil
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pandas as pd
from splink import DuckDBAPI, Linker
from splink.internals.exceptions import SplinkException

from packages.core.models.node import CuzNode
from packages.entity_resolution.splink_settings import (
    ASSUMED_DUPLICATE_RATE,
    FUSION_AUTO_THRESHOLD,
    HUMAN_REVIEW_LOWER_THRESHOLD,
    build_settings_dict,
    prior_match_probability,
)

logger = logging.getLogger("er-probabilistic")

# Sources jamais candidates à la fusion : un nœud IaC (déclaré) et son équivalent réel (observé)
# doivent rester distincts, c'est ce qui permet de mesurer le drift (P2.3).
EXCLUDED_SOURCES = frozenset({"terraform"})

# Réentraînement sur décisions humaines (P2.6). Seules les paires validées « merge » servent (positifs) ;
# estimate_m_from_pairwise_labels de Splink ignore les scores d'étiquette et un niveau jamais observé
# recevrait m = 0 : on mélange donc fréquences observées et m d'expert (pseudo-comptes).
MIN_POSITIVE_LABELS = 20
M_SMOOTHING_STRENGTH = 20


class InsufficientLabelsError(Exception):
    """Pas assez de paires validées pour recalibrer sans dégrader le modèle."""


MODEL_DIR = Path(__file__).resolve().parents[2] / "config" / "er"


def model_path(tenant_id: str) -> Path:
    return MODEL_DIR / f"{tenant_id}_splink_model.json"


def normalize_name(name: str | None) -> str | None:
    """Casse et séparateurs normalisés : « payroll-orders » ≡ « PAYROLL_ORDERS »."""
    return re.sub(r"[\s_\-]+", "", (name or "").lower()) or None


def same_type_pairs(df: pd.DataFrame) -> int:
    return int(sum(n * (n - 1) // 2 for n in df["node_type"].value_counts()))


def exact_name_u(df: pd.DataFrame) -> float:
    """u du niveau « nom identique » : fréquence des noms identiques parmi les paires de même type,
    plancher à 1 paire. L'échantillonnage aléatoire ne l'observe presque jamais (u non estimé)."""
    pairs = identical = 0
    for _, group in df.groupby("node_type"):
        n = len(group)
        pairs += n * (n - 1) // 2
        identical += int(sum(c * (c - 1) // 2 for c in group["name"].dropna().value_counts()))
    return max(identical, 1) / max(pairs, 1)


def _record(
    unique_id: str, node_type: str, name: str | None, ip: Any, source: str
) -> dict[str, Any]:
    return {
        "unique_id": unique_id,
        "node_type": node_type,
        "name": normalize_name(name),
        "ip_address": str(ip).strip() if ip else None,
        "source": source,
    }


def nodes_to_dataframe(nodes: Iterable[CuzNode]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            _record(
                n.id,
                n.node_type.value,
                n.name,
                n.attributes.get("ip_address"),
                n.sources[0] if n.sources else "unknown",
            )
            for n in nodes
        ]
    )


def graph_to_dataframe(tenant_id: str) -> pd.DataFrame:
    """Lit les nœuds du tenant dans Neo4j (lecture seule)."""
    from packages.graph.client import Neo4jClient

    with Neo4jClient.get_driver().session() as session:
        rows = session.run(
            "MATCH (n:CuzNode {tenant_id: $t}) RETURN n.id AS id, n.node_type AS node_type, "
            "n.name AS name, n.attributes AS attrs, n.sources AS sources",
            t=tenant_id,
        ).data()
    records = []
    for r in rows:
        try:
            ip = json.loads(r["attrs"] or "{}").get("ip_address")
        except json.JSONDecodeError:
            ip = None
        records.append(
            _record(r["id"], r["node_type"], r["name"], ip, (r["sources"] or ["unknown"])[0])
        )
    return pd.DataFrame(records)


class ProbabilisticResolver:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.linker: Linker | None = None
        # Étape d'entraînement -> "ok" | "skipped: <raison>" ; un modèle partiellement entraîné
        # doit le dire, pas le cacher.
        self.training_report: dict[str, str] = {}

    def _step(self, name: str, fn: Any) -> None:
        try:
            fn()
            self.training_report[name] = "ok"
        except SplinkException as e:
            reason = str(e).splitlines()[0][:200]
            self.training_report[name] = f"skipped: {reason}"
            logger.warning("entraînement %s ignoré : %s", name, reason)

    def train(self, df: pd.DataFrame, max_pairs: float = 1e6) -> None:
        """Paramètres Fellegi-Sunter : prior (hypothèse explicite) et m (valeurs d'expert) sont
        spécifiés ; seuls les u sont estimés sur les données, par échantillonnage aléatoire."""

        self.linker = Linker(
            DuckDBAPI().register(df),
            build_settings_dict(
                prior_match_probability(len(df), same_type_pairs(df)), exact_name_u(df)
            ),
        )
        training = self.linker.training
        self.training_report = {}
        self.training_report["prior_probability"] = (
            f"assumed: {ASSUMED_DUPLICATE_RATE:.0%} de doublons avant P2.5 (guide), non estimé"
        )
        self._step(
            "u_probabilities",
            lambda: training.estimate_u_using_random_sampling(max_pairs=max_pairs),
        )
        # m fixés (EXPERT_M_PROBABILITIES) : l'EM non supervisé est dégénéré quand le graphe contient
        # très peu de doublons (il apprend l'inverse : m=0 sur « nom très proche »).
        self.training_report["m_probabilities"] = (
            "specified: valeurs d'expert, à ré-estimer sur étiquettes humaines (P2.6)"
        )

    def save_model(self, path: Path | None = None) -> Path:
        assert self.linker is not None, "modèle non entraîné"
        target = path or model_path(self.tenant_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.linker.misc.save_model_to_json(str(target), overwrite=True)
        return target

    def load_model(self, df: pd.DataFrame, path: Path | None = None) -> None:
        """Recharge un modèle entraîné sans réentraînement."""
        source = path or model_path(self.tenant_id)
        self.linker = Linker(DuckDBAPI().register(df), Path(source))

    def predict_candidate_pairs(self, df: pd.DataFrame) -> pd.DataFrame:
        """Paires candidates avec leur match_probability, limitées aux sources différentes."""
        assert self.linker is not None, "modèle non chargé"
        predictions = self.linker.inference.predict(
            threshold_match_probability=HUMAN_REVIEW_LOWER_THRESHOLD
        ).as_pandas_dataframe()
        if predictions.empty:
            return predictions
        source = df.set_index("unique_id")["source"]
        src_l, src_r = (
            predictions["unique_id_l"].map(source),
            predictions["unique_id_r"].map(source),
        )
        keep = (src_l != src_r) & ~src_l.isin(EXCLUDED_SOURCES) & ~src_r.isin(EXCLUDED_SOURCES)
        return predictions[keep].reset_index(drop=True)

    @staticmethod
    def classify(predictions_df: pd.DataFrame) -> dict[str, pd.DataFrame]:
        p = predictions_df["match_probability"]
        return {
            "auto_merge": predictions_df[p >= FUSION_AUTO_THRESHOLD],
            "needs_human_review": predictions_df[
                (p >= HUMAN_REVIEW_LOWER_THRESHOLD) & (p < FUSION_AUTO_THRESHOLD)
            ],
            "rejected": predictions_df[p < HUMAN_REVIEW_LOWER_THRESHOLD],
        }


def _gamma_levels(comparison: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """(gamma, niveau) hors niveau NULL. Le modèle sérialisé n'a pas de clé gamma : les niveaux sont
    ordonnés du plus spécifique au plus général, donc gamma = nb_niveaux - 1 - position."""
    levels = [lv for lv in comparison["comparison_levels"] if not lv.get("is_null_level")]
    return [(len(levels) - 1 - i, lv) for i, lv in enumerate(levels)]


def recalibrate_m(
    model: dict[str, Any],
    gamma_counts: dict[str, dict[int, int]],
    strength: int = M_SMOOTHING_STRENGTH,
) -> dict[str, Any]:
    """Fonction pure : m_new = (observés + strength * m_ancien) / (N + strength), par comparaison.
    `gamma_counts` : output_column_name -> {gamma -> nb de paires validées}."""
    for comparison in model["comparisons"]:
        counts = gamma_counts.get(comparison["output_column_name"], {})
        levels = _gamma_levels(comparison)
        n = sum(counts.get(gamma, 0) for gamma, _ in levels)
        if n == 0:
            continue
        for gamma, lv in levels:
            lv["m_probability"] = (counts.get(gamma, 0) + strength * lv["m_probability"]) / (
                n + strength
            )
    return model


def _m_snapshot(model: dict[str, Any]) -> dict[str, list[float]]:
    return {
        c["output_column_name"]: [round(lv["m_probability"], 4) for _, lv in _gamma_levels(c)]
        for c in model["comparisons"]
    }


def retrain_from_merged_pairs(
    resolver: "ProbabilisticResolver",
    df: pd.DataFrame,
    merged_pairs: list[tuple[str, str]],
    path: Path | None = None,
) -> dict[str, Any]:
    """Recalibre les m du modèle sur les paires validées « merge ». L'ancien modèle est conservé
    (*.prev.json). Lève InsufficientLabelsError sous MIN_POSITIVE_LABELS paires exploitables."""
    target = path or model_path(resolver.tenant_id)
    resolver.load_model(df, target)
    assert resolver.linker is not None
    predictions = resolver.linker.inference.predict().as_pandas_dataframe()
    wanted = {frozenset(p) for p in merged_pairs}
    labelled = predictions[
        [
            frozenset(p) in wanted
            for p in zip(predictions["unique_id_l"], predictions["unique_id_r"], strict=True)
        ]
    ]
    if len(labelled) < MIN_POSITIVE_LABELS:
        raise InsufficientLabelsError(
            f"{len(labelled)} paire(s) validée(s) exploitable(s) sur {len(wanted)} ; "
            f"minimum {MIN_POSITIVE_LABELS}"
        )
    model = json.loads(target.read_text(encoding="utf-8"))
    before = _m_snapshot(model)
    counts = {
        c["output_column_name"]: {
            int(k): int(v)
            for k, v in labelled[f"gamma_{c['output_column_name']}"].value_counts().items()
        }
        for c in model["comparisons"]
    }
    recalibrate_m(model, counts)
    shutil.copyfile(target, target.with_suffix(".prev.json"))
    target.write_text(json.dumps(model, indent=2), encoding="utf-8")
    resolver.load_model(df, target)
    return {"labels_used": len(labelled), "m_before": before, "m_after": _m_snapshot(model)}


def measure_duplicate_rate(total_nodes: int, duplicate_pairs: int) -> float:
    """Part (%) de nœuds en doublon estimé : paires >= seuil de fusion auto / nœuds."""
    if total_nodes == 0:
        return 0.0
    return round(100 * duplicate_pairs / total_nodes, 2)


def compute_stats(
    tenant_id: str, df: pd.DataFrame, resolver: ProbabilisticResolver
) -> dict[str, Any]:
    classified = resolver.classify(resolver.predict_candidate_pairs(df))
    auto, review = len(classified["auto_merge"]), len(classified["needs_human_review"])
    return {
        "tenant_id": tenant_id,
        "total_nodes": len(df),
        "auto_merge_pairs": auto,
        "pending_review_pairs": review,
        "duplicate_rate_pct": measure_duplicate_rate(len(df), auto),
        "thresholds": {
            "auto_merge": FUSION_AUTO_THRESHOLD,
            "human_review_lower": HUMAN_REVIEW_LOWER_THRESHOLD,
        },
        "duplicate_rate_basis": "estimated_from_model",  # pas de paires confirmées humainement
    }


def main() -> int:
    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--train", action="store_true", help="réentraîne et sauvegarde le modèle")
    parser.add_argument(
        "--retrain-from-decisions",
        action="store_true",
        help="recalibre les m sur les paires validées (er_decisions)",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    df = graph_to_dataframe(args.tenant)
    resolver = ProbabilisticResolver(args.tenant)
    if args.retrain_from_decisions:
        from services.api import er_audit
        from services.api.audit import get_pool

        async def _merged() -> list[tuple[str, str]]:
            try:
                return await er_audit.merged_pairs(args.tenant)
            finally:
                await (await get_pool()).close()

        try:
            report = retrain_from_merged_pairs(resolver, df, asyncio.run(_merged()))
        except InsufficientLabelsError as e:
            logger.error("réentraînement refusé : %s", e)
            return 1
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.train or not model_path(args.tenant).exists():
        resolver.train(df)
        logger.info("modèle sauvegardé : %s", resolver.save_model())
    else:
        resolver.load_model(df)
    stats = compute_stats(args.tenant, df, resolver)
    if resolver.training_report:
        stats["training_report"] = resolver.training_report
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
