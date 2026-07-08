import math
from datetime import datetime, timedelta, timezone
from packages.core.models.enums import NodeType

# Demi-vie par type de nœud (en jours)
HALF_LIFE_DAYS: dict = {
    NodeType.VIRTUAL_MACHINE:  7,
    NodeType.SERVER:           7,
    NodeType.USER:             1,
    NodeType.SERVICE_ACCOUNT:  1,
    NodeType.APPLICATION:      30,
    NodeType.REPOSITORY:       14,
    NodeType.NETWORK:          7,
    NodeType.VULNERABILITY:    3,
    NodeType.THIRD_PARTY:      90,
    NodeType.DATABASE:         14,
    NodeType.CLUSTER:          7,
}
DEFAULT_HALF_LIFE = 14   # Jours, si le type n'est pas spécifié

def compute_freshness(node_type: NodeType, last_seen: datetime) -> float:
    """Décroissance exponentielle : f(t) = exp(-λt) avec λ = ln(2) / half_life."""
    half_life = HALF_LIFE_DAYS.get(node_type, DEFAULT_HALF_LIFE)
    lambda_decay = math.log(2) / half_life
    elapsed_days = (datetime.now(timezone.utc) - last_seen.replace(tzinfo=timezone.utc)).total_seconds() / 86400
    score = math.exp(-lambda_decay * elapsed_days)
    return round(max(0.0, min(1.0, score)), 4)