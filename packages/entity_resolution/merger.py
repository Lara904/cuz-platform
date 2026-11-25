# packages/entity-resolution/merger.py
from datetime import UTC, datetime
from typing import cast

from packages.core.models.node import CuzNode
from packages.core.scoring import compute_confidence, compute_freshness
from packages.entity_resolution.resolver import DeterministicResolver


class NodeMerger:
    def __init__(self, resolver: DeterministicResolver):
        self.resolver = resolver

    def merge_or_create(self, incoming: CuzNode) -> CuzNode:
        existing_id, is_dup = self.resolver.resolve(incoming)
        if not is_dup:
            self.resolver.register(incoming)
            return incoming
        existing = self.resolver.get(cast(str, existing_id))
        merged = self._merge(cast(CuzNode, existing), incoming)
        self.resolver.register(merged)  # ré-indexe les clés fortes élargies
        return merged

    def _merge(self, existing: CuzNode, incoming: CuzNode) -> CuzNode:
        """Newest wins pour les attributs. Union pour sources/external_ids.

        BUG CORRIGÉ (DEC-012) : node_type était figé sur existing.node_type, donc
        jamais mis à jour par un merge -- un cmdb_ci_service ServiceNow requalifié
        en BUSINESS_FUNCTION par mapper.py::map_ci() (promotion par criticité)
        restait bloqué sur son ancien node_type (ex: APPLICATION) dès qu'un
        deuxième événement pour le même sys_id était vu dans la même exécution de
        GraphWriter (resolver en mémoire -> is_dup=True -> _merge()). Le fix de
        writer.py (ON MATCH SET, 76c83d8) ne suffisait donc pas : le node_type
        qui lui arrivait était déjà figé en amont par ce merge. Incohérence qui
        trahissait déjà le bug : compute_freshness() ci-dessous utilisait
        incoming.node_type alors que le node_type réellement conservé était celui
        d'existing -- les deux doivent être de la même source de vérité.
        Newest wins pour node_type, comme pour le reste des attributs."""
        now = datetime.now(UTC)
        merged_ext = {**existing.external_ids, **incoming.external_ids}
        merged_sources = list(set(existing.sources + incoming.sources))
        merged_attrs = {**existing.attributes, **incoming.attributes}
        merged_tags = {**existing.tags, **incoming.tags}
        new_confidence = compute_confidence(merged_sources)
        new_freshness = compute_freshness(incoming.node_type, now)
        return CuzNode(
            id=existing.id,
            tenant_id=existing.tenant_id,
            node_type=incoming.node_type,
            name=incoming.name,
            external_id=existing.external_id,
            external_ids=merged_ext,
            confidence_score=new_confidence,
            freshness_score=new_freshness,
            sources=merged_sources,
            created_at=existing.created_at,
            updated_at=now,
            last_seen=now,
            attributes=merged_attrs,
            tags=merged_tags,
        )
