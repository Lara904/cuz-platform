# packages/entity-resolution/owner_linker.py
"""Résout l'arête OWNS entre un USER (Entra ID) et un REPOSITORY (Gitea).

Aucun connecteur ne produit cette arête directement : le repo Gitea ne
connaît son propriétaire que par un nom d'utilisateur Gitea (attributes
['owner']), pas par une référence à un CuzNode USER. La résolution se fait
donc ici, après que les deux nœuds ont été vus par l'entity resolution,
sur la convention AcmeCorp : le nom d'utilisateur Gitea correspond à la
partie locale de l'UPN Entra ID (djana.dev <-> djana.dev@acmecorp...).

Limite assumée : si cette convention de nommage ne tient pas chez un futur
client (Stellantis ou autre), ce linker doit être adapté ou remplacé par
un identifiant explicite côté Gitea (ex: mapping manuel owner -> UPN).
Ce n'est pas un mécanisme d'entity resolution probabiliste (réservé à
Splink en P2.5) : c'est un rapprochement déterministe sur une convention
documentée, dans le même esprit que le reste de P1.6."""
import json
from pathlib import Path
from typing import Optional
from packages.core.models.node import CuzNode
from packages.core.models.edge import CuzEdge
from packages.core.models.enums import EdgeType
from packages.core.scoring import compute_confidence, compute_freshness
from datetime import datetime, timezone

DEFAULT_OWNER_MAPPING_PATH = Path(__file__).resolve().parents[2] / "config" / "gitea_owner_mapping.json"


def load_owner_mapping(path: Path = DEFAULT_OWNER_MAPPING_PATH) -> dict[str, str]:
    """Mapping explicite repo Gitea (full_name) -> partie locale de l'UPN du owner.
    Prime sur l'attribut owner de Gitea, qui désigne l'organisation (acmecorp)."""
    if not path.exists():
        return {}
    return {k.lower(): v.lower() for k, v in json.loads(path.read_text(encoding="utf-8")).items()}


class OwnerLinker:
    def __init__(self, owner_mapping: dict[str, str] | None = None):
        # index par tenant : (tenant_id, upn_local_part) -> CuzNode
        # (un USER d'un tenant ne doit jamais être lié à un repo d'un autre)
        self._users: dict[tuple[str, str], CuzNode] = {}
        self._owner_mapping = owner_mapping if owner_mapping is not None else load_owner_mapping()

    def _owner_login(self, repo_node: CuzNode) -> str | None:
        full_name = (repo_node.attributes.get("full_name") or "").lower()
        return self._owner_mapping.get(full_name) or repo_node.attributes.get("owner")

    def register_user(self, user_node: CuzNode) -> None:
        """À appeler pour chaque USER une fois résolu par le NodeMerger (P1.6)."""
        upn = user_node.attributes.get("upn")
        if not upn or "@" not in upn:
            return
        local_part = upn.split("@")[0].lower()
        self._users[(user_node.tenant_id, local_part)] = user_node

    def resolve_owns_edge(self, repo_node: CuzNode) -> Optional[CuzEdge]:
        """Retourne une CuzEdge OWNS (user -> repo) si le owner du repo
        correspond à un USER déjà enregistré du même tenant, None sinon
        (ne pas fabriquer un lien sur une correspondance incertaine)."""
        owner = self._owner_login(repo_node)
        if not owner:
            return None
        user_node = self._users.get((repo_node.tenant_id, owner.lower()))
        if not user_node:
            return None
        last_seen = datetime.now(timezone.utc)
        return CuzEdge(
            tenant_id=repo_node.tenant_id,
            edge_type=EdgeType.OWNS,
            source_id=user_node.id,
            target_id=repo_node.id,
            confidence_score=compute_confidence(["gitea", "entra_id"]),
            freshness_score=compute_freshness(repo_node.node_type, last_seen),
            sources=["gitea", "entra_id"],
            last_seen=last_seen,
            attributes={"resolution_method": "owner_upn_local_part_match"},
        )