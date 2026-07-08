# packages/core/scoring/confidence.py

# Poids de confiance par source (configurables par tenant)
DEFAULT_SOURCE_WEIGHTS: dict[str, float] = {
    "servicenow": 0.80,  # CMDB — données saisies manuellement
    "azure": 0.95,  # API cloud — données auto-collectées
    "entra_id": 0.95,  # IAM Microsoft
    "github": 0.90,  # Source de vérité pour le code
    "kubernetes": 0.92,  # API K8s
    "sentinel": 0.85,  # Alertes sécurité
    "terraform": 0.88,  # IaC
}


def compute_confidence(
    sources: list[str], weights: dict[str, float] = DEFAULT_SOURCE_WEIGHTS
) -> float:
    """Formule bayésienne : confidence = 1 - prod(1 - s_i) pour toutes les sources."""
    if not sources:
        return 0.0
    product = 1.0
    for source in sources:
        s_i = weights.get(source, 0.5)  # 0.5 par défaut si source inconnue
        product *= 1.0 - s_i
    return round(1.0 - product, 4)
