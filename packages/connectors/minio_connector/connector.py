# packages/connectors/minio/connector.py
import os
import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator, List
from minio import Minio
from minio.error import S3Error
from packages.core.interfaces.connector import IConnector
from packages.core.models.events import RawEvent, EventType
from packages.connectors.minio_connector.mapper import MinIOMapper

class MinIOConnector(IConnector):
    def __init__(self, tenant_id: str, endpoint: str,
                 access_key: str, secret_key: str, secure: bool = False):
        self.tenant_id = tenant_id
        self.client = Minio(endpoint, access_key=access_key,
                            secret_key=secret_key, secure=secure)
        self.mapper = MinIOMapper(tenant_id)
        self.endpoint = endpoint

    async def test_connection(self) -> bool:
        try:
            list(self.client.list_buckets())
            return True
        except Exception:
            return False

    def _is_bucket_public(self, bucket_name: str) -> bool:
        try:
            policy = json.loads(self.client.get_bucket_policy(bucket_name))
            for statement in policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", {})
                # Supporte "*" et {"AWS": ["*"]} et {"AWS": "*"}
                if principal == "*":
                    return True
                aws = principal.get("AWS", [])
                if "*" in (aws if isinstance(aws, list) else [aws]):
                    return True
            return False
        except Exception:
            return False


    def _get_bucket_tags(self, bucket_name: str) -> dict:
        try:
            tags = self.client.get_bucket_tags(bucket_name)
            return dict(tags) if tags else {}
        except Exception:
            return {}

    def _list_objects_with_tags(self, bucket_name: str) -> List[dict]:
        objects = []
        try:
            for obj in self.client.list_objects(bucket_name, recursive=True):
                obj_tags = {}
                try:
                    t = self.client.get_object_tags(bucket_name, obj.object_name)
                    obj_tags = dict(t) if t else {}
                except Exception:
                    pass
                objects.append({
                    "name": obj.object_name,
                    "size": obj.size,
                    "last_modified": obj.last_modified.isoformat()
                        if obj.last_modified else None,
                    "tags": obj_tags,
                })
        except Exception:
            pass
        return objects

    async def pull_full(self) -> List[RawEvent]:
        events = []
        buckets = self.client.list_buckets()
        for bucket in buckets:
            is_public = self._is_bucket_public(bucket.name)
            bucket_tags = self._get_bucket_tags(bucket.name)
            objects = self._list_objects_with_tags(bucket.name)
            raw = {
                "bucket_name": bucket.name,
                "creation_date": bucket.creation_date.isoformat()
                    if bucket.creation_date else None,
                "is_public": is_public,
                "tags": bucket_tags,
                "objects": objects,
                "endpoint": self.endpoint,
            }
            events.append(RawEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                source="minio",
                event_type=EventType.NODE_CREATED,
                timestamp=datetime.now(timezone.utc),
                raw_data=raw,
            ))
        return events

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        while True:
            events = await self.pull_full()
            for e in events:
                yield e
            await asyncio.sleep(3600)