# packages/ingestion/normalizer.py
import uuid

from packages.connectors.entra_id.mapper import EntraIDMapper
from packages.connectors.gitea.mapper import GiteaMapper
from packages.connectors.minio_connector.mapper import MinIOMapper
from packages.connectors.servicenow.mapper import ServiceNowMapper
from packages.core.models.events import NormalizedEvent, RawEvent


class Normalizer:
    def __init__(self):
        self._mappers: dict = {}
        self._repo_node_cache: dict = {}  # (tenant_id, repo_external_id) -> CuzNode

    def _get_mapper(self, source: str, tenant_id: str):
        key = (source, tenant_id)
        if key not in self._mappers:
            if source == "servicenow":
                self._mappers[key] = ServiceNowMapper(tenant_id)
            elif source == "minio":
                self._mappers[key] = MinIOMapper(tenant_id)
            elif source == "entra_id":
                self._mappers[key] = EntraIDMapper(tenant_id)
            elif source == "gitea":
                self._mappers[key] = GiteaMapper(tenant_id)
        return self._mappers.get(key)

    def normalize(self, raw: RawEvent) -> list[NormalizedEvent]:
        """Retourne une LISTE de NormalizedEvent (peut être vide) : un repo
        Gitea peut produire 1 événement nœud + N événements arête (une par
        dépendance). Changement de signature par rapport à la v1.0, qui
        retournait Optional[NormalizedEvent]."""
        mapper = self._get_mapper(raw.source, raw.tenant_id)
        if not mapper:
            return []

        results: list[NormalizedEvent] = []

        if raw.source == "servicenow":
            node = mapper.map_ci(raw.raw_data["table"], raw.raw_data["record"])
            if node:
                results.append(self._wrap(raw, node=node))

        elif raw.source == "minio":
            node = mapper.map_bucket(raw.raw_data)
            results.append(self._wrap(raw, node=node))

        elif raw.source == "entra_id":
            obj_type = raw.raw_data.get("object_type")
            if obj_type == "user":
                node = mapper.map_user(raw.raw_data["record"])
                results.append(self._wrap(raw, node=node))
            elif obj_type == "service_principal":
                node = mapper.map_service_principal(raw.raw_data["record"])
                results.append(self._wrap(raw, node=node))

        elif raw.source == "gitea":
            obj_type = raw.raw_data.get("object_type")
            if obj_type == "repository":
                repo_node = mapper.map_repo(raw.raw_data)
                results.append(self._wrap(raw, node=repo_node))
                cache_key = (raw.tenant_id, raw.raw_data["repo_id"])
                self._repo_node_cache[cache_key] = repo_node

                # FIX-2 : produire un événement nœud + un événement arête
                # par dépendance, en réutilisant map_repo_dependency_edge()
                # déjà présent dans GiteaMapper (jusqu'ici jamais appelé).
                for dep in raw.raw_data.get("dependencies", []):
                    dep_node = mapper.map_dependency(dep)
                    results.append(self._wrap(raw, node=dep_node))
                    edge = mapper.map_repo_dependency_edge(repo_node, dep_node)
                    results.append(self._wrap(raw, edge=edge))

        return results

    def _wrap(self, raw: RawEvent, node=None, edge=None) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            raw_event_id=raw.event_id,
            tenant_id=raw.tenant_id,
            source=raw.source,
            event_type=raw.event_type,
            timestamp=raw.timestamp,
            node=node,
            edge=edge,
        )
