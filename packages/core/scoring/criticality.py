# packages/core/scoring/criticality.py
"""Convention DICT légère : attributes['criticality'] = {'D': 1-4, 'I': 1-4, 'C': 1-4, 'T': 1-4}.

Aucune pondération par contexte de conformité n'est calculée ici : c'est un jugement
humain, documenté à part (docs/dict-convention.md).
"""
from typing import Optional

from packages.core.models.node import CuzNode

DICT_AXES = ("D", "I", "C", "T")


def node_criticality_order(node: CuzNode) -> Optional[int]:
    """Max des axes DICT renseignés (1-4), None si rien n'est renseigné.
    Ne jamais interpoler ni supposer une valeur par défaut."""
    dict_attrs = node.attributes.get("criticality")
    if not isinstance(dict_attrs, dict):
        return None
    values = [dict_attrs.get(axis) for axis in DICT_AXES]
    values = [v for v in values if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 4]
    return max(values) if values else None


def max_criticality_along_path(node_criticalities: list[Optional[int]]) -> Optional[int]:
    """Propage la criticité max le long d'un chemin DEPENDS_ON / SUPPORTS.
    Simple max : pas de pondération, pas de décroissance avec la distance."""
    known = [c for c in node_criticalities if c is not None]
    return max(known) if known else None
