# packages/entity-resolution/merger.py
from datetime import datetime, timezone
from typing import List
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
        existing = self.resolver.get(existing_id)
        merged = self._merge(existing, incoming)
        self.resolver.register(merged)  # ré-indexe les clés fortes élargies
        return merged

    def _merge(self, existing: CuzNode, incoming: CuzNode) -> CuzNode:
        """Newest wins pour les attributs. Union pour sources/external_ids."""
        now = datetime.now(timezone.utc)
        merged_ext = {**existing.external_ids, **incoming.external_ids}
        merged_sources = list(set(existing.sources + incoming.sources))
        merged_attrs = {**existing.attributes, **incoming.attributes}
        merged_tags = {**existing.tags, **incoming.tags}
        new_confidence = compute_confidence(merged_sources)
        new_freshness = compute_freshness(incoming.node_type, now)
        return CuzNode(
            id=existing.id,
            tenant_id=existing.tenant_id,
            node_type=existing.node_type,
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