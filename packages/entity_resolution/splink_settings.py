# packages/entity_resolution/splink_settings.py
"""Configuration Splink 5 pour CUz : comparaisons sur les champs réellement présents sur les
CuzNode (name, attributes.ip_address). created_at n'est pas comparé : c'est la date d'ingestion
du scan, pas une date de création de la ressource. Un modèle par tenant, pas de fuite cross-tenant
(cf. critère P2.14)."""

import splink.comparison_library as cl
from splink import SettingsCreator, block_on

FUSION_AUTO_THRESHOLD = 0.92
HUMAN_REVIEW_LOWER_THRESHOLD = 0.60

# Hypothèse de départ : ~10 % de nœuds en doublon, taux que le resolver déterministe de P1.6 laisse
# selon le guide (objectif P2.5 : le ramener sous 2 %). La règle « même nom » n'est pas utilisée pour
# estimer le prior : elle ne trouve rien quand les doublons ont des noms différents.
ASSUMED_DUPLICATE_RATE = 0.10


def prior_match_probability(n_nodes: int, same_type_pairs: int) -> float:
    """Probabilité que deux nœuds de même type tirés au hasard soient le même (population de
    candidats = celle du blocage et du u « nom identique ») : doublons supposés / paires."""
    if n_nodes < 2 or same_type_pairs < 1:
        return 1e-3
    return min(0.5, ASSUMED_DUPLICATE_RATE * n_nodes / same_type_pairs)


def build_settings(prior: float) -> SettingsCreator:
    return SettingsCreator(
        link_type="dedupe_only",
        unique_id_column_name="unique_id",
        probability_two_random_records_match=prior,
        comparisons=[
            cl.JaroWinklerAtThresholds("name", [0.9, 0.7]),
            cl.ExactMatch("ip_address"),
        ],
        # Les doublons visés sont de même type ; un candidat partage un préfixe de nom ou une IP.
        blocking_rules_to_generate_predictions=[
            block_on("node_type", "substr(name, 1, 3)"),
            block_on("node_type", "ip_address"),
        ],
        retain_matching_columns=True,
        retain_intermediate_calculation_columns=False,
    )


# m = P(niveau observé | vrai doublon), fixés par expertise : l'EM non supervisé converge vers une
# solution dégénérée tant que le graphe contient très peu de doublons. À ré-estimer sur étiquettes
# humaines (P2.6) via estimate_m_from_pairwise_labels. Ordre = niveaux hors niveau NULL.
EXPERT_M_PROBABILITIES: dict[str, list[float]] = {
    "name": [0.45, 0.35, 0.15, 0.05],  # exact, JW >= 0.9, JW >= 0.7, autre
    "ip_address": [0.80, 0.20],  # exact, autre
}


def build_settings_dict(prior: float, exact_name_u: float) -> dict:
    """Settings Splink avec m_probability spécifiés ; u estimé sur les données, sauf le niveau
    « nom identique » (jamais observé par échantillonnage) dont le u est fourni par l'appelant."""
    settings = build_settings(prior).create_settings_dict("duckdb")
    for comparison in settings["comparisons"]:
        m_values = iter(EXPERT_M_PROBABILITIES[comparison["output_column_name"]])
        for level in comparison["comparison_levels"]:
            if not level.get("is_null_level"):
                level["m_probability"] = next(m_values)
                if (
                    comparison["output_column_name"] == "name"
                    and "Exact match" in level["label_for_charts"]
                ):
                    level["u_probability"] = exact_name_u
    return settings
