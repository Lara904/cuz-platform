# packages/entity-resolution/resolver.py
from typing import Dict, List, Optional, Tuple
from packages.core.models.node import CuzNode

STRONG_ID_KEYS = {
    "servicenow": "servicenow",
    "minio":      "minio",
    "entra_id":   "entra_id",
    "gitea":      "gitea",
}

class DeterministicResolver:
    """Match sur identifiants forts — doublons < 10% garantis."""

    def __init__(self):
        # index: (tenant_id, source, external_id) -> CuzNode.id
        self._index: Dict[Tuple[str, str, str], str] = {}
        # stockage: node.id -> CuzNode
        self._store: Dict[str, CuzNode] = {}

    def _get_keys(self, node: CuzNode) -> List[Tuple[str, str, str]]:
        # Toutes les clés fortes du nœud : une fusion multi-sources doit être
        # reconnue par chacune de ses sources, pas seulement la première.
        return [
            (node.tenant_id, source, ext_id)
            for source, ext_id in node.external_ids.items()
            if ext_id and source in STRONG_ID_KEYS
        ]

    def resolve(self, node: CuzNode) -> Tuple[Optional[str], bool]:
        """Retourne (existing_node_id | None, is_duplicate)."""
        for key in self._get_keys(node):
            if key in self._index:
                return self._index[key], True
        return None, False

    def register(self, node: CuzNode) -> None:
        """Enregistrer un nœud (et toutes ses clés fortes) dans l'index."""
        self._store[node.id] = node
        for key in self._get_keys(node):
            self._index[key] = node.id

    def get(self, node_id: str) -> Optional[CuzNode]:
        return self._store.get(node_id)
