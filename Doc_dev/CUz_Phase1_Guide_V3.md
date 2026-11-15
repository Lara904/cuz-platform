**CUz**

*Cartographie Unifiée du SI*

**GUIDE PHASE 1 --- MVP CARTOGRAPHIE**

**Version :** 3.0 (bifurcation) --- Septembre 2026, sur la base de la v1.0 de Juillet 2026

**Terrain :** 100 % AcmeCorp local --- zéro Stellantis

**Développeuse :** Solo, Fedora, Python 3.12, Docker Compose actif, venv activé

**Critère minimal Phase 1 (révisé V3) :** ATTACK-PATH-001-PARTIAL détecté (3 maillons) ; la version à 5 maillons devient critère de sortie P2.1

**Durée estimée :** Mois 1---6

**Dépendances :** Phase 0 complète ✅ + AC.0→AC.8 validés ✅

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ NOTE SUR CETTE VERSION** Ce document est la version complète et à jour du Guide Phase 1, réécrite par le Plan de dev V3 (bifurcation, pas un changement total). Les sections P1.1 à P1.4, P1.9 à P1.15, les prérequis et les règles non négociables reprennent le contenu de la v1.0 sans modification de fond. Les sections P1.5, P1.6 (complétée), P1.7 et P1.8 intègrent les correctifs FIX-1/FIX-2/FIX-3 identifiés en confrontant le guide au code réel du dépôt GitHub. Trois nouvelles sous-phases (P1.16, P1.17, P1.18) sont ajoutées en fin de phase. Rien n\'est supprimé : la checklist de sortie d\'origine est conservée et complétée.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1. Introduction

La Phase 1 construit le premier graphe unifié du Système d\'Information d\'AcmeCorp, avec détection de findings cross-domaine et un dashboard opérationnel. Elle est développée et validée entièrement en local. Aucun accès Stellantis n\'est requis.

Le critère de succès minimal est non négociable : ATTACK-PATH-001 doit être détecté automatiquement. Ce finding prouve qu\'un utilisateur sans MFA (djana.dev) peut accéder au repo backend, lequel contient qs@6.5.2 affectée par CVE-2022-24999 (CVSS 9.8), dépendance déployée dans un pod exposé publiquement, avec accès au bucket acmecorp-public. Aucun outil mono-domaine ne peut détecter ce chemin --- c\'est le différenciateur clé de CUz.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  ⚠️ AC.9 (connexion connecteurs + scan initial + \>200 nœuds + 5 findings) N\'EST PAS FAIT en entrée de Phase 1. Elle sera réalisée en deux temps : • Scan partiel après P1.4 : 4 connecteurs enregistrés, ingestion de données brutes. • Scan complet après P1.7 : graphe peuplé, ATTACK-PATH-001 détectable.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1.1 Règles non négociables

🚨 RÈGLE 1 : Aucun connecteur n\'écrit directement dans Neo4j. Tout transit par Redpanda (topic cuz.raw.{tenant_id}).

🚨 RÈGLE 2 : Tout nœud et toute arête porte confidence_score ET freshness_score. Sans exception. Aucun nœud ne peut exister sans ces deux attributs.

🚨 RÈGLE 3 : Aucune action automatique sur un nœud dont confidence_score \< 0.7.

⚠️ RÈGLE 4 : L\'audit trail est immuable --- PostgreSQL append-only, aucune suppression de log.

⚠️ RÈGLE 5 : Un connecteur = un dossier dans packages/connectors/. Hérite de IConnector. Contient connector.py, mapper.py, tests/.

2. Récapitulatif des prérequis

Avant de démarrer la moindre étape de Phase 1, valider CHAQUE item de la checklist suivante. Ne pas démarrer P1.1 si un item est rouge.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Ref**      **Critère**
  ------------ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Phase 0      docker compose ps → 6 services healthy (Neo4j, Redpanda, PostgreSQL, Redis, Qdrant, OPA)

  Phase 0      pytest packages/core/tests/ → 50 tests verts (CuzNode, CuzEdge, enums)

  Phase 0      pytest packages/core/tests/test_scoring.py → 20 cas verts (compute_confidence, compute_freshness)

  Phase 0      Interface IConnector stable dans packages/core/interfaces/connector.py

  Phase 0      API FastAPI : POST /api/v1/tenants → tenant acmecorp créé, auth JWT fonctionnel, RBAC 4 rôles

  Phase 0      CI/CD GitHub Actions : badge vert sur main

  AC.1         k3d cluster acmecorp : kubectl get nodes → 3 nœuds Ready

  AC.1         kubectl get pods -n production → ≥5 pods Running, pod legacy-job avec privileged=true

  AC.2         MinIO : 3 buckets créés, acmecorp-public accessible sans credentials, clients_pii.csv tagué contains_pii=true

  AC.3         Gitea : org acmecorp, 4 repos dont backend avec qs@6.5.2 dans package.json

  AC.4         Entra ID dev tenant actif, 6 utilisateurs dont djana.dev et svc-pipeline sans MFA, app CUz enregistrée

  AC.5         ServiceNow PDI dev387275.service-now.com : \>20 CIs, CI Acme-Payment-SaaS sans exit_plan_status

  AC.6         tests/fixtures/acmecorp.tfstate présent avec drift (acmecorp-archive absent de MinIO)

  AC.7         tests/fixtures/acmecorp_cves.json : CVE-2022-24999 (CVSS 9.8), CVE-2021-3918

  AC.8         Script ac8_scenarios.sh → 8 scénarios validés dont ATTACK-PATH-001 (5/5 maillons en place)

  .env         Variables présentes : ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET, ENTRA_TENANT_NAME, MINIO_USER, MINIO_PASSWORD, GITEA_ADMIN_TOKEN, SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.1 --- Connecteur ServiceNow CMDB

**Objectif :** Ingérer les 6 tables CMDB du PDI AcmeCorp en mode poll delta horaire + scan quotidien, et mapper les CIs ServiceNow vers des CuzNode.

Fichiers à créer

📄 packages/connectors/servicenow/__init__.py

📄 packages/connectors/servicenow/connector.py

📄 packages/connectors/servicenow/mapper.py

📄 packages/connectors/servicenow/tests/__init__.py

📄 packages/connectors/servicenow/tests/test_servicenow.py

connector.py

# packages/connectors/servicenow/connector.py

import os

import asyncio

import httpx

from datetime import datetime, timezone

from typing import AsyncIterator, List, Optional

from packages.core.interfaces.connector import IConnector

from packages.core.models.events import RawEvent, EventType

from packages.connectors.servicenow.mapper import ServiceNowMapper

import uuid

CMDB_TABLES = [

\"cmdb_ci_server\",

\"cmdb_ci_appl\",

\"cmdb_ci_database\",

\"cmdb_ci_ip_network\",

\"cmdb_ci_service\",

\"cmdb_rel_ci\",

]

class ServiceNowConnector(IConnector):

def __init__(self, tenant_id: str, instance_url: str,

username: str, password: str):

self.tenant_id = tenant_id

self.instance_url = instance_url.rstrip(\"/\")

self.auth = (username, password)

self.mapper = ServiceNowMapper(tenant_id)

async def test_connection(self) -\> bool:

url = f\"{self.instance_url}/api/now/table/cmdb_ci_server\"

params = {\"sysparm_limit\": 1, \"sysparm_fields\": \"sys_id\"}

async with httpx.AsyncClient(auth=self.auth, timeout=15) as client:

r = await client.get(url, params=params)

return r.status_code == 200

async def _fetch_table(

self,

client: httpx.AsyncClient,

table: str,

updated_after: Optional[datetime] = None,

) -\> List[dict]:

url = f\"{self.instance_url}/api/now/table/{table}\"

params = {

\"sysparm_limit\": 500,

\"sysparm_display_value\": \"false\",

}

if updated_after:

ts = updated_after.strftime(\"%Y-%m-%d %H:%M:%S\")

params[\"sysparm_query\"] = f\"sys_updated_on\>{ts}\"

results = []

offset = 0

while True:

params[\"sysparm_offset\"] = offset

r = await client.get(url, params=params)

r.raise_for_status()

batch = r.json().get(\"result\", [])

results.extend(batch)

if len(batch) \< 500:

break

offset += 500

return results

async def pull_full(self) -\> List[RawEvent]:

events = []

async with httpx.AsyncClient(auth=self.auth, timeout=30) as client:

for table in CMDB_TABLES:

records = await self._fetch_table(client, table)

for rec in records:

events.append(RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"servicenow\",

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data={\"table\": table, \"record\": rec},

schema_version=\"1.0\",

))

return events

async def subscribe_events(self) -\> AsyncIterator[RawEvent]:

\"\"\"Poll delta toutes les heures; scan quotidien complet.\"\"\"

last_pull = None

while True:

updated_after = last_pull

last_pull = datetime.now(timezone.utc)

async with httpx.AsyncClient(auth=self.auth, timeout=30) as client:

for table in CMDB_TABLES:

records = await self._fetch_table(

client, table, updated_after

)

for rec in records:

yield RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"servicenow\",

event_type=EventType.NODE_UPDATED,

timestamp=datetime.now(timezone.utc),

raw_data={\"table\": table, \"record\": rec},

)

await asyncio.sleep(3600) # poll horaire

mapper.py

# packages/connectors/servicenow/mapper.py

from datetime import datetime, timezone

from typing import Optional

from packages.core.models.node import CuzNode

from packages.core.models.enums import NodeType

from packages.core.scoring import compute_confidence,

compute_freshness

TABLE_TO_NODE_TYPE = {

\"cmdb_ci_server\": NodeType.SERVER,

\"cmdb_ci_appl\": NodeType.APPLICATION,

\"cmdb_ci_database\": NodeType.DATABASE,

\"cmdb_ci_ip_network\": NodeType.NETWORK,

\"cmdb_ci_service\": NodeType.APPLICATION,

\"cmdb_rel_ci\": None, # arête --- traité séparément

}

class ServiceNowMapper:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

def map_ci(self, table: str, rec: dict) -\> Optional[CuzNode]:

node_type = TABLE_TO_NODE_TYPE.get(table)

if not node_type:

return None

name = rec.get(\"name\") or rec.get(\"sys_id\", \"unknown\")

last_seen = datetime.now(timezone.utc)

return CuzNode(

tenant_id=self.tenant_id,

node_type=node_type,

name=name,

external_id=rec.get(\"sys_id\"),

external_ids={\"servicenow\": rec.get(\"sys_id\", \"\")},

confidence_score=compute_confidence([\"servicenow\"]),

freshness_score=compute_freshness(node_type, last_seen),

sources=[\"servicenow\"],

last_seen=last_seen,

attributes={

\"operational_status\": rec.get(\"operational_status\"),

\"environment\": rec.get(\"environment\"),

\"sys_class_name\": rec.get(\"sys_class_name\"),

\"ip_address\": rec.get(\"ip_address\"),

\"os\": rec.get(\"os\"),

\"exit_plan_status\": rec.get(\"exit_plan_status\"),

\"vendor\": rec.get(\"vendor\"),

\"support_group\": rec.get(\"support_group\"),

},

tags={

\"source\": \"servicenow\",

\"cmdb_table\": table,

},

)

tests/test_servicenow.py

# packages/connectors/servicenow/tests/test_servicenow.py

import pytest

import asyncio

from unittest.mock import AsyncMock, MagicMock, patch

from packages.connectors.servicenow.connector import

ServiceNowConnector

from packages.connectors.servicenow.mapper import ServiceNowMapper

from packages.core.models.enums import NodeType

TENANT = \"acmecorp\"

INSTANCE = \"https://dev387275.service-now.com\"

\@pytest.fixture

def connector():

import os

return ServiceNowConnector(

tenant_id=TENANT,

instance_url=os.getenv(\"SERVICENOW_URL\", INSTANCE),

username=os.getenv(\"SERVICENOW_USER\", \"admin\"),

password=os.getenv(\"SERVICENOW_PASSWORD\", \"\"),

)

\@pytest.mark.asyncio

async def test_connection_returns_true(connector):

\"\"\"test_connection() doit retourner True sur le PDI réel.\"\"\"

result = await connector.test_connection()

assert result is True

\@pytest.mark.asyncio

async def test_pull_full_returns_events(connector):

events = await connector.pull_full()

assert len(events) \> 20, f\"Attendu \>20 événements, obtenu

{len(events)}\"

for e in events:

assert e.tenant_id == TENANT

assert e.source == \"servicenow\"

def test_mapper_server():

mapper = ServiceNowMapper(TENANT)

rec = {\"sys_id\": \"abc123\", \"name\": \"web-srv-01\",

\"operational_status\": \"1\", \"ip_address\": \"10.0.0.1\"}

node = mapper.map_ci(\"cmdb_ci_server\", rec)

assert node is not None

assert node.node_type == NodeType.SERVER

assert node.external_id == \"abc123\"

assert 0.0 \<= node.confidence_score \<= 1.0

assert 0.0 \<= node.freshness_score \<= 1.0

def test_mapper_application():

mapper = ServiceNowMapper(TENANT)

rec = {\"sys_id\": \"def456\", \"name\": \"payment-app\",

\"exit_plan_status\": None}

node = mapper.map_ci(\"cmdb_ci_appl\", rec)

assert node.node_type == NodeType.APPLICATION

assert node.attributes[\"exit_plan_status\"] is None

def test_mapper_rel_ci_returns_none():

mapper = ServiceNowMapper(TENANT)

rec = {\"sys_id\": \"rel001\", \"parent\": \"a\", \"child\": \"b\"}

node = mapper.map_ci(\"cmdb_rel_ci\", rec)

assert node is None # cmdb_rel_ci → arête, pas nœud

\@pytest.mark.asyncio

async def test_pull_covers_all_6_tables(connector):

events = await connector.pull_full()

tables = {e.raw_data[\"table\"] for e in events}

expected = {\"cmdb_ci_server\",\"cmdb_ci_appl\",\"cmdb_ci_database\",

\"cmdb_ci_ip_network\",\"cmdb_ci_service\",\"cmdb_rel_ci\"}

for t in expected:

assert t in tables, f\"Table manquante : {t}\"

**✅ Critères de sortie P1.1**

  -----------------------------------------------------------------------
  ✓ pytest packages/connectors/servicenow/tests/ -v → tous verts

  -----------------------------------------------------------------------

P1.2 --- Connecteur Stockage objet MinIO/S3

**Objectif :** Ingérer buckets, permissions, tags et métadonnées MinIO. Détecter les buckets publics, non chiffrés, contenant des données PII.

Fichiers à créer

📄 packages/connectors/minio/__init__.py

📄 packages/connectors/minio/connector.py

📄 packages/connectors/minio/mapper.py

📄 packages/connectors/minio/tests/__init__.py

📄 packages/connectors/minio/tests/test_minio.py

connector.py

# packages/connectors/minio/connector.py

import os

import asyncio

import uuid

from datetime import datetime, timezone

from typing import AsyncIterator, List

from minio import Minio

from minio.error import S3Error

from packages.core.interfaces.connector import IConnector

from packages.core.models.events import RawEvent, EventType

from packages.connectors.minio.mapper import MinIOMapper

class MinIOConnector(IConnector):

def __init__(self, tenant_id: str, endpoint: str,

access_key: str, secret_key: str, secure: bool = False):

self.tenant_id = tenant_id

self.client = Minio(endpoint, access_key=access_key,

secret_key=secret_key, secure=secure)

self.mapper = MinIOMapper(tenant_id)

self.endpoint = endpoint

async def test_connection(self) -\> bool:

try:

list(self.client.list_buckets())

return True

except Exception:

return False

def _is_bucket_public(self, bucket_name: str) -\> bool:

try:

policy = self.client.get_bucket_policy(bucket_name)

return \'\"Effect\":\"Allow\"\' in policy and \'\"Principal\":\"*\"\'

in policy

except Exception:

return False

def _get_bucket_tags(self, bucket_name: str) -\> dict:

try:

tags = self.client.get_bucket_tags(bucket_name)

return dict(tags) if tags else {}

except Exception:

return {}

def _list_objects_with_tags(self, bucket_name: str) -\> List[dict]:

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

\"name\": obj.object_name,

\"size\": obj.size,

\"last_modified\": obj.last_modified.isoformat()

if obj.last_modified else None,

\"tags\": obj_tags,

})

except Exception:

pass

return objects

async def pull_full(self) -\> List[RawEvent]:

events = []

buckets = self.client.list_buckets()

for bucket in buckets:

is_public = self._is_bucket_public(bucket.name)

bucket_tags = self._get_bucket_tags(bucket.name)

objects = self._list_objects_with_tags(bucket.name)

raw = {

\"bucket_name\": bucket.name,

\"creation_date\": bucket.creation_date.isoformat()

if bucket.creation_date else None,

\"is_public\": is_public,

\"tags\": bucket_tags,

\"objects\": objects,

\"endpoint\": self.endpoint,

}

events.append(RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"minio\",

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data=raw,

))

return events

async def subscribe_events(self) -\> AsyncIterator[RawEvent]:

while True:

events = await self.pull_full()

for e in events:

yield e

await asyncio.sleep(3600)

mapper.py

# packages/connectors/minio/mapper.py

from datetime import datetime, timezone

from packages.core.models.node import CuzNode

from packages.core.models.enums import NodeType

from packages.core.scoring import compute_confidence,

compute_freshness

class MinIOMapper:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

def map_bucket(self, raw: dict) -\> CuzNode:

last_seen = datetime.now(timezone.utc)

contains_pii = any(

obj.get(\"tags\", {}).get(\"contains_pii\") == \"true\"

for obj in raw.get(\"objects\", [])

)

return CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.STORAGE,

name=raw[\"bucket_name\"],

external_id=raw[\"bucket_name\"],

external_ids={\"minio\": raw[\"bucket_name\"]},

confidence_score=compute_confidence([\"minio\"]),

freshness_score=compute_freshness(NodeType.STORAGE, last_seen),

sources=[\"minio\"],

last_seen=last_seen,

attributes={

\"is_public\": raw.get(\"is_public\", False),

\"contains_pii\": contains_pii,

\"object_count\": len(raw.get(\"objects\", [])),

\"endpoint\": raw.get(\"endpoint\"),

\"creation_date\": raw.get(\"creation_date\"),

},

tags={

**raw.get(\"tags\", {}),

\"source\": \"minio\",

},

)

tests/test_minio.py

# packages/connectors/minio/tests/test_minio.py

import pytest

import os

from packages.connectors.minio.connector import MinIOConnector

from packages.connectors.minio.mapper import MinIOMapper

from packages.core.models.enums import NodeType

\@pytest.fixture

def connector():

return MinIOConnector(

tenant_id=\"acmecorp\",

endpoint=os.getenv(\"MINIO_ENDPOINT\", \"localhost:9000\"),

access_key=os.getenv(\"MINIO_USER\", \"acmeadmin\"),

secret_key=os.getenv(\"MINIO_PASSWORD\", \"\"),

secure=False,

)

\@pytest.mark.asyncio

async def test_connection(connector):

assert await connector.test_connection() is True

\@pytest.mark.asyncio

async def test_pull_full_returns_3_buckets(connector):

events = await connector.pull_full()

bucket_names = {e.raw_data[\"bucket_name\"] for e in events}

assert \"acmecorp-data\" in bucket_names

assert \"acmecorp-logs\" in bucket_names

assert \"acmecorp-public\" in bucket_names

\@pytest.mark.asyncio

async def test_acmecorp_public_is_flagged(connector):

events = await connector.pull_full()

pub = next(e for e in events if e.raw_data[\"bucket_name\"] ==

\"acmecorp-public\")

assert pub.raw_data[\"is_public\"] is True

\@pytest.mark.asyncio

async def test_clients_pii_csv_detected(connector):

events = await connector.pull_full()

pub = next(e for e in events if e.raw_data[\"bucket_name\"] ==

\"acmecorp-public\")

pii_objs = [o for o in pub.raw_data[\"objects\"]

if o.get(\"tags\", {}).get(\"contains_pii\") == \"true\"]

assert len(pii_objs) \> 0

def test_mapper_bucket_node_type():

mapper = MinIOMapper(\"acmecorp\")

raw = {\"bucket_name\": \"acmecorp-public\", \"is_public\": True,

\"objects\": [{\"name\": \"clients_pii.csv\", \"tags\":

{\"contains_pii\": \"true\"}}],

\"tags\": {}, \"endpoint\": \"localhost:9000\"}

node = mapper.map_bucket(raw)

assert node.node_type == NodeType.STORAGE

assert node.attributes[\"is_public\"] is True

assert node.attributes[\"contains_pii\"] is True

assert 0.0 \<= node.confidence_score \<= 1.0

  -----------------------------------------------------------------------
  Installer le SDK MinIO : pip install minio

  -----------------------------------------------------------------------

**✅ Critères de sortie P1.2**

  -----------------------------------------------------------------------
  ✓ pytest packages/connectors/minio/tests/ -v → tous verts

  -----------------------------------------------------------------------

P1.3 --- Connecteur Entra ID (Microsoft Graph)

**Objectif :** Ingérer Users, Service Principals, Groups, Enterprise Apps via Microsoft Graph. Capturer méthodes MFA et expirations credentials. AuditLog.Read.All (sign-in logs) sera activé en Phase 2.

Fichiers à créer

📄 packages/connectors/entra_id/__init__.py

📄 packages/connectors/entra_id/connector.py

📄 packages/connectors/entra_id/mapper.py

📄 packages/connectors/entra_id/tests/__init__.py

📄 packages/connectors/entra_id/tests/test_entra_id.py

connector.py

# packages/connectors/entra_id/connector.py

import os

import asyncio

import uuid

import httpx

from datetime import datetime, timezone

from typing import AsyncIterator, List, Optional

from packages.core.interfaces.connector import IConnector

from packages.core.models.events import RawEvent, EventType

GRAPH_BASE = \"https://graph.microsoft.com/v1.0\"

class EntraIDConnector(IConnector):

def __init__(self, tenant_id_cuz: str, entra_tenant_id: str,

client_id: str, client_secret: str):

self.tenant_id = tenant_id_cuz # CUz tenant

self.entra_tenant_id = entra_tenant_id # Azure tenant

self.client_id = client_id

self.client_secret = client_secret

self._token: Optional[str] = None

self._token_expiry: Optional[datetime] = None

async def _get_token(self) -\> str:

if self._token and self._token_expiry and datetime.now(timezone.utc)

\< self._token_expiry:

return self._token

url =

f\"https://login.microsoftonline.com/{self.entra_tenant_id}/oauth2/v2.0/token\"

data = {

\"grant_type\": \"client_credentials\",

\"client_id\": self.client_id,

\"client_secret\": self.client_secret,

\"scope\": \"https://graph.microsoft.com/.default\",

}

async with httpx.AsyncClient(timeout=20) as client:

r = await client.post(url, data=data)

r.raise_for_status()

resp = r.json()

self._token = resp[\"access_token\"]

expires_in = resp.get(\"expires_in\", 3600)

from datetime import timedelta

self._token_expiry = datetime.now(timezone.utc) +

timedelta(seconds=expires_in - 60)

return self._token

async def test_connection(self) -\> bool:

try:

token = await self._get_token()

headers = {\"Authorization\": f\"Bearer {token}\"}

async with httpx.AsyncClient(timeout=15) as client:

r = await client.get(f\"{GRAPH_BASE}/organization\", headers=headers)

return r.status_code == 200

except Exception:

return False

async def _get_all_pages(self, url: str) -\> List[dict]:

token = await self._get_token()

headers = {\"Authorization\": f\"Bearer {token}\"}

results = []

async with httpx.AsyncClient(timeout=30) as client:

while url:

r = await client.get(url, headers=headers)

r.raise_for_status()

data = r.json()

results.extend(data.get(\"value\", []))

url = data.get(\"@odata.nextLink\")

return results

async def _get_mfa_methods(self, user_id: str) -\> List[dict]:

token = await self._get_token()

headers = {\"Authorization\": f\"Bearer {token}\"}

url = f\"{GRAPH_BASE}/users/{user_id}/authentication/methods\"

try:

async with httpx.AsyncClient(timeout=20) as client:

r = await client.get(url, headers=headers)

if r.status_code == 200:

return r.json().get(\"value\", [])

except Exception:

pass

return []

async def pull_full(self) -\> List[RawEvent]:

events = []

users = await self._get_all_pages(

f\"{GRAPH_BASE}/users?\$select=id,displayName,userPrincipalName,\"

f\"accountEnabled,createdDateTime,passwordPolicies\"

)

for user in users:

mfa_methods = await self._get_mfa_methods(user[\"id\"])

strong = [m for m in mfa_methods

if m.get(\"@odata.type\") not in

[\"#microsoft.graph.passwordAuthenticationMethod\"]]

user[\"mfa_methods\"] = mfa_methods

user[\"has_mfa\"] = len(strong) \> 0

events.append(RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"entra_id\",

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data={\"object_type\": \"user\", \"record\": user},

))

sps = await self._get_all_pages(

f\"{GRAPH_BASE}/servicePrincipals?\$select=id,displayName,\"

f\"appId,accountEnabled,passwordCredentials\"

)

for sp in sps:

events.append(RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"entra_id\",

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data={\"object_type\": \"service_principal\", \"record\": sp},

))

return events

async def subscribe_events(self) -\> AsyncIterator[RawEvent]:

while True:

for e in await self.pull_full():

yield e

await asyncio.sleep(21600) # poll 6h

mapper.py

# packages/connectors/entra_id/mapper.py

from datetime import datetime, timezone

from packages.core.models.node import CuzNode

from packages.core.models.enums import NodeType

from packages.core.scoring import compute_confidence,

compute_freshness

class EntraIDMapper:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

def map_user(self, rec: dict) -\> CuzNode:

last_seen = datetime.now(timezone.utc)

return CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.USER,

name=rec.get(\"displayName\", \"unknown\"),

external_id=rec.get(\"id\"),

external_ids={\"entra_id\": rec.get(\"id\", \"\")},

confidence_score=compute_confidence([\"entra_id\"]),

freshness_score=compute_freshness(NodeType.USER, last_seen),

sources=[\"entra_id\"],

last_seen=last_seen,

attributes={

\"upn\": rec.get(\"userPrincipalName\"),

\"account_enabled\": rec.get(\"accountEnabled\"),

\"has_mfa\": rec.get(\"has_mfa\", False),

\"mfa_methods\": [m.get(\"@odata.type\")

for m in rec.get(\"mfa_methods\", [])],

\"created_at\": rec.get(\"createdDateTime\"),

},

tags={\"source\": \"entra_id\", \"object_type\": \"user\"},

)

def map_service_principal(self, rec: dict) -\> CuzNode:

last_seen = datetime.now(timezone.utc)

creds = rec.get(\"passwordCredentials\", [])

expired = any(

c.get(\"endDateTime\") and

c[\"endDateTime\"] \< datetime.now(timezone.utc).isoformat()

for c in creds

)

return CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.SERVICE_ACCOUNT,

name=rec.get(\"displayName\", \"unknown\"),

external_id=rec.get(\"id\"),

external_ids={\"entra_id\": rec.get(\"id\", \"\")},

confidence_score=compute_confidence([\"entra_id\"]),

freshness_score=compute_freshness(NodeType.SERVICE_ACCOUNT,

last_seen),

sources=[\"entra_id\"],

last_seen=last_seen,

attributes={

\"app_id\": rec.get(\"appId\"),

\"account_enabled\": rec.get(\"accountEnabled\"),

\"has_expired_creds\": expired,

},

tags={\"source\": \"entra_id\", \"object_type\":

\"service_principal\"},

)

tests/test_entra_id.py

# packages/connectors/entra_id/tests/test_entra_id.py

import pytest

import os

from packages.connectors.entra_id.connector import EntraIDConnector

from packages.connectors.entra_id.mapper import EntraIDMapper

from packages.core.models.enums import NodeType

\@pytest.fixture

def connector():

return EntraIDConnector(

tenant_id_cuz=\"acmecorp\",

entra_tenant_id=os.getenv(\"ENTRA_TENANT_ID\"),

client_id=os.getenv(\"ENTRA_CLIENT_ID\"),

client_secret=os.getenv(\"ENTRA_CLIENT_SECRET\"),

)

\@pytest.mark.asyncio

async def test_connection(connector):

assert await connector.test_connection() is True

\@pytest.mark.asyncio

async def test_pull_full_returns_users(connector):

events = await connector.pull_full()

users = [e for e in events if e.raw_data.get(\"object_type\") ==

\"user\"]

assert len(users) \>= 6, f\"Attendu \>=6 users, obtenu {len(users)}\"

\@pytest.mark.asyncio

async def test_djana_dev_no_mfa(connector):

events = await connector.pull_full()

users = [e for e in events if e.raw_data.get(\"object_type\") ==

\"user\"]

djana = next(

(e for e in users

if \"djana\" in

e.raw_data[\"record\"].get(\"userPrincipalName\",\"\").lower()),

None

)

assert djana is not None, \"djana.dev non trouvée\"

assert djana.raw_data[\"record\"][\"has_mfa\"] is False

\@pytest.mark.asyncio

async def test_svc_pipeline_no_mfa(connector):

events = await connector.pull_full()

users = [e for e in events if e.raw_data.get(\"object_type\") ==

\"user\"]

svc = next(

(e for e in users

if \"svc-pipeline\" in

e.raw_data[\"record\"].get(\"userPrincipalName\",\"\").lower()),

None

)

assert svc is not None, \"svc-pipeline non trouvé\"

assert svc.raw_data[\"record\"][\"has_mfa\"] is False

def test_mapper_user_has_mfa_false():

mapper = EntraIDMapper(\"acmecorp\")

rec = {\"id\": \"uid1\", \"displayName\": \"Djana Dev\",

\"userPrincipalName\": \"djana.dev@acmecorp.onmicrosoft.com\",

\"accountEnabled\": True, \"has_mfa\": False,

\"mfa_methods\": [], \"createdDateTime\": \"2024-01-01T00:00:00Z\"}

node = mapper.map_user(rec)

assert node.node_type == NodeType.USER

assert node.attributes[\"has_mfa\"] is False

assert node.attributes[\"upn\"] ==

\"djana.dev@acmecorp.onmicrosoft.com\"

  -----------------------------------------------------------------------------------------------------------------------------------
  Installer : pip install httpx Permissions Graph requises : User.Read.All, UserAuthenticationMethod.Read.All, Application.Read.All

  -----------------------------------------------------------------------------------------------------------------------------------

**✅ Critères de sortie P1.3**

  -----------------------------------------------------------------------
  ✓ pytest packages/connectors/entra_id/tests/ -v → tous verts

  -----------------------------------------------------------------------

P1.4 --- Connecteur Git (Gitea)

**Objectif :** Ingérer repos, teams, membres, dépendances (package.json, requirements.txt) et alertes de sécurité via l\'API Gitea. Activer les webhooks.

Fichiers à créer

📄 packages/connectors/gitea/__init__.py

📄 packages/connectors/gitea/connector.py

📄 packages/connectors/gitea/mapper.py

📄 packages/connectors/gitea/tests/__init__.py

📄 packages/connectors/gitea/tests/test_gitea.py

connector.py

# packages/connectors/gitea/connector.py

import os

import json

import asyncio

import uuid

import httpx

from datetime import datetime, timezone

from typing import AsyncIterator, List, Optional

from packages.core.interfaces.connector import IConnector

from packages.core.models.events import RawEvent, EventType

class GiteaConnector(IConnector):

def __init__(self, tenant_id: str, base_url: str,

admin_token: str, org: str = \"acmecorp\"):

self.tenant_id = tenant_id

self.base_url = base_url.rstrip(\"/\")

self.org = org

self.headers = {

\"Authorization\": f\"token {admin_token}\",

\"Content-Type\": \"application/json\",

}

async def test_connection(self) -\> bool:

async with httpx.AsyncClient(headers=self.headers, timeout=15) as c:

r = await c.get(f\"{self.base_url}/api/v1/user\")

return r.status_code == 200

async def _get_repos(self, client: httpx.AsyncClient) -\>

List[dict]:

r = await client.get(

f\"{self.base_url}/api/v1/orgs/{self.org}/repos\",

params={\"limit\": 50}

)

r.raise_for_status()

return r.json()

async def _get_file(self, client: httpx.AsyncClient,

owner: str, repo: str, path: str) -\> Optional[str]:

r = await client.get(

f\"{self.base_url}/api/v1/repos/{owner}/{repo}/raw/{path}\"

)

if r.status_code == 200:

return r.text

return None

def _parse_dependencies(self, package_json: str,

requirements_txt: str) -\> List[dict]:

deps = []

if package_json:

try:

pkg = json.loads(package_json)

for name, version in {

**pkg.get(\"dependencies\", {}),

**pkg.get(\"devDependencies\", {}),

}.items():

deps.append({

\"name\": name,

\"version\": version.lstrip(\"\^\~\>=\"),

\"ecosystem\": \"npm\",

})

except Exception:

pass

if requirements_txt:

for line in requirements_txt.splitlines():

line = line.strip()

if line and not line.startswith(\"#\"):

parts = line.split(\"==\")

deps.append({

\"name\": parts[0].strip(),

\"version\": parts[1].strip() if len(parts) \> 1 else \"unknown\",

\"ecosystem\": \"pypi\",

})

return deps

async def _register_webhook(self, client: httpx.AsyncClient,

owner: str, repo: str,

callback_url: str) -\> bool:

existing = await client.get(

f\"{self.base_url}/api/v1/repos/{owner}/{repo}/hooks\"

)

hooks = existing.json() if existing.status_code == 200 else []

if any(h.get(\"config\", {}).get(\"url\") == callback_url for h in

hooks):

return True

payload = {

\"active\": True,

\"config\": {\"url\": callback_url, \"content_type\": \"json\"},

\"events\": [\"push\", \"create\", \"delete\", \"pull_request\"],

\"type\": \"gitea\",

}

r = await client.post(

f\"{self.base_url}/api/v1/repos/{owner}/{repo}/hooks\",

json=payload

)

return r.status_code in (200, 201)

async def pull_full(self) -\> List[RawEvent]:

events = []

webhook_url = os.getenv(

\"CUZ_WEBHOOK_URL\",

\"http://localhost:8000/api/v1/webhooks/gitea\"

)

async with httpx.AsyncClient(headers=self.headers, timeout=30) as

client:

repos = await self._get_repos(client)

for repo in repos:

owner = repo[\"owner\"][\"login\"]

name = repo[\"name\"]

pkg_json = await self._get_file(client, owner, name,

\"package.json\")

reqs_txt = await self._get_file(client, owner, name,

\"requirements.txt\")

deps = self._parse_dependencies(

pkg_json or \"\", reqs_txt or \"\"

)

await self._register_webhook(client, owner, name, webhook_url)

events.append(RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=self.tenant_id,

source=\"gitea\",

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data={

\"object_type\": \"repository\",

\"repo_id\": str(repo[\"id\"]),

\"full_name\": repo[\"full_name\"],

\"name\": name,

\"owner\": owner,

\"private\": repo.get(\"private\", True),

\"default_branch\": repo.get(\"default_branch\", \"main\"),

\"dependencies\": deps,

},

))

return events

async def subscribe_events(self) -\> AsyncIterator[RawEvent]:

while True:

for e in await self.pull_full():

yield e

await asyncio.sleep(86400) # scan quotidien

mapper.py

# packages/connectors/gitea/mapper.py

from datetime import datetime, timezone

from typing import List, Tuple

from packages.core.models.node import CuzNode

from packages.core.models.edge import CuzEdge

from packages.core.models.enums import NodeType, EdgeType

from packages.core.scoring import compute_confidence,

compute_freshness

class GiteaMapper:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

def map_repo(self, raw: dict) -\> CuzNode:

last_seen = datetime.now(timezone.utc)

return CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.REPOSITORY,

name=raw[\"name\"],

external_id=raw[\"repo_id\"],

external_ids={\"gitea\": raw[\"repo_id\"]},

confidence_score=compute_confidence([\"gitea\"]),

freshness_score=compute_freshness(NodeType.REPOSITORY, last_seen),

sources=[\"gitea\"],

last_seen=last_seen,

attributes={

\"full_name\": raw.get(\"full_name\"),

\"private\": raw.get(\"private\", True),

\"default_branch\": raw.get(\"default_branch\", \"main\"),

\"owner\": raw.get(\"owner\"),

},

tags={\"source\": \"gitea\"},

)

def map_dependency(self, dep: dict) -\> CuzNode:

last_seen = datetime.now(timezone.utc)

dep_name = f\"{dep[\'name\']}@{dep[\'version\']}\"

return CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.VULNERABILITY,

name=dep_name,

external_id=dep_name,

external_ids={\"gitea\": dep_name},

confidence_score=compute_confidence([\"gitea\"]),

freshness_score=compute_freshness(NodeType.VULNERABILITY, last_seen),

sources=[\"gitea\"],

last_seen=last_seen,

attributes={

\"package_name\": dep[\"name\"],

\"version\": dep[\"version\"],

\"ecosystem\": dep.get(\"ecosystem\", \"unknown\"),

},

tags={\"source\": \"gitea\", \"node_subtype\": \"dependency\"},

)

def map_repo_dependency_edge(

self, repo_node: CuzNode, dep_node: CuzNode

) -\> CuzEdge:

last_seen = datetime.now(timezone.utc)

return CuzEdge(

tenant_id=self.tenant_id,

edge_type=EdgeType.DEPENDS_ON,

source_id=repo_node.id,

target_id=dep_node.id,

confidence_score=compute_confidence([\"gitea\"]),

freshness_score=compute_freshness(NodeType.REPOSITORY, last_seen),

sources=[\"gitea\"],

)

tests/test_gitea.py

# packages/connectors/gitea/tests/test_gitea.py

import pytest

import os

from packages.connectors.gitea.connector import GiteaConnector

from packages.connectors.gitea.mapper import GiteaMapper

from packages.core.models.enums import NodeType, EdgeType

\@pytest.fixture

def connector():

return GiteaConnector(

tenant_id=\"acmecorp\",

base_url=os.getenv(\"GITEA_URL\", \"http://localhost:3000\"),

admin_token=os.getenv(\"GITEA_ADMIN_TOKEN\", \"\"),

org=\"acmecorp\",

)

\@pytest.mark.asyncio

async def test_connection(connector):

assert await connector.test_connection() is True

\@pytest.mark.asyncio

async def test_pull_full_returns_4_repos(connector):

events = await connector.pull_full()

repos = [e for e in events if e.raw_data.get(\"object_type\") ==

\"repository\"]

assert len(repos) == 4, f\"Attendu 4 repos, obtenu {len(repos)}\"

\@pytest.mark.asyncio

async def test_backend_repo_has_qs_dependency(connector):

events = await connector.pull_full()

backend = next(

(e for e in events if e.raw_data.get(\"name\") == \"backend\"), None

)

assert backend is not None, \"Repo \'backend\' non trouvé\"

deps = backend.raw_data.get(\"dependencies\", [])

qs_dep = next((d for d in deps if d[\"name\"] == \"qs\"), None)

assert qs_dep is not None, \"Dépendance qs non trouvée dans backend\"

assert qs_dep[\"version\"] == \"6.5.2\"

def test_mapper_dependency_node_type():

mapper = GiteaMapper(\"acmecorp\")

dep = {\"name\": \"qs\", \"version\": \"6.5.2\", \"ecosystem\":

\"npm\"}

node = mapper.map_dependency(dep)

assert node.node_type == NodeType.VULNERABILITY

assert node.attributes[\"package_name\"] == \"qs\"

assert node.attributes[\"version\"] == \"6.5.2\"

def test_mapper_edge_type():

mapper = GiteaMapper(\"acmecorp\")

from packages.core.models.node import CuzNode

from packages.core.models.enums import NodeType

repo = mapper.map_repo({\"repo_id\": \"1\", \"name\": \"backend\",

\"full_name\": \"acmecorp/backend\",

\"private\": True, \"default_branch\": \"main\",

\"owner\": \"acmecorp\"})

dep = mapper.map_dependency({\"name\": \"qs\", \"version\": \"6.5.2\",

\"ecosystem\": \"npm\"})

edge = mapper.map_repo_dependency_edge(repo, dep)

assert edge.edge_type == EdgeType.DEPENDS_ON

**✅ Critères de sortie P1.4**

  -----------------------------------------------------------------------
  ✓ pytest packages/connectors/gitea/tests/ -v → tous verts

  -----------------------------------------------------------------------

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  ⚡ Point de synchronisation AC.9 --- Scan partiel (après P1.4) \> Les 4 connecteurs de base sont opérationnels. On peut enregistrer chacun sur le tenant acmecorp et lancer un premier scan partiel. Le graphe ne sera pas encore complet (pas de pipeline normalisé ni de graph writer), mais on valide la connectivité.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Commandes curl exactes --- Enregistrement des connecteurs

# 1. Obtenir un token JWT admin

export TOKEN=\$(curl -s -X POST

http://localhost:8000/api/v1/auth/token

-H \"Content-Type: application/json\"

-d

\'{\"username\":\"admin\",\"password\":\"\<CUZ_ADMIN_PASSWORD\>\"}\'

\| jq -r .access_token)

# 2. Enregistrer le connecteur ServiceNow

curl -s -X POST

http://localhost:8000/api/v1/tenants/acmecorp/connectors/

-H \"Authorization: Bearer \$TOKEN\"

-H \"Content-Type: application/json\"

-d \'{

\"connector_type\": \"servicenow\",

\"credentials\": {

\"instance_url\": \"\'\$SERVICENOW_URL\'\",

\"username\": \"\'\$SERVICENOW_USER\'\",

\"password\": \"\'\$SERVICENOW_PASSWORD\'\"

}

}\' \| jq .

# 3. Enregistrer le connecteur MinIO

curl -s -X POST

http://localhost:8000/api/v1/tenants/acmecorp/connectors/

-H \"Authorization: Bearer \$TOKEN\"

-H \"Content-Type: application/json\"

-d \'{

\"connector_type\": \"minio\",

\"credentials\": {

\"endpoint\": \"localhost:9000\",

\"access_key\": \"\'\$MINIO_USER\'\",

\"secret_key\": \"\'\$MINIO_PASSWORD\'\",

\"secure\": false

}

}\' \| jq .

# 4. Enregistrer le connecteur Entra ID

curl -s -X POST

http://localhost:8000/api/v1/tenants/acmecorp/connectors/

-H \"Authorization: Bearer \$TOKEN\"

-H \"Content-Type: application/json\"

-d \'{

\"connector_type\": \"entra_id\",

\"credentials\": {

\"tenant_id\": \"\'\$ENTRA_TENANT_ID\'\",

\"client_id\": \"\'\$ENTRA_CLIENT_ID\'\",

\"client_secret\": \"\'\$ENTRA_CLIENT_SECRET\'\"

}

}\' \| jq .

# 5. Enregistrer le connecteur Gitea

curl -s -X POST

http://localhost:8000/api/v1/tenants/acmecorp/connectors/

-H \"Authorization: Bearer \$TOKEN\"

-H \"Content-Type: application/json\"

-d \'{

\"connector_type\": \"gitea\",

\"credentials\": {

\"base_url\": \"http://localhost:3000\",

\"admin_token\": \"\'\$GITEA_ADMIN_TOKEN\'\",

\"org\": \"acmecorp\"

}

}\' \| jq .

# 6. Tester chaque connecteur

for CONN_ID in \$(curl -s

http://localhost:8000/api/v1/tenants/acmecorp/connectors/

-H \"Authorization: Bearer \$TOKEN\" \| jq -r \'.[].id\'); do

echo \"=== Test connecteur \$CONN_ID ===\"

curl -s -X POST

\"http://localhost:8000/api/v1/tenants/acmecorp/connectors/\$CONN_ID/test\"

-H \"Authorization: Bearer \$TOKEN\" \| jq .

done

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  À ce stade, les connecteurs sont enregistrés et leur test_connection() retourne 200. Les données ne sont pas encore persistées dans Neo4j --- cela nécessite le pipeline (P1.5) et le graph writer (P1.7). Continuer avec P1.5.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Complément P1.1 (Plan V3, FIX-1) --- mapper.py, modification ciblée de map_ci()

Le mapper actuel mappe systématiquement cmdb_ci_service vers NodeType.APPLICATION. Résultat : aucun nœud THIRD_PARTY n\'est jamais créé depuis ServiceNow, et la règle DORA-THIRD-PARTY-001 (§P1.8) ne peut jamais matcher, y compris sur le CI Acme-Payment-SaaS pourtant prévu à cet effet dans AC.5. Ce correctif remplace uniquement la fonction map_ci() ci-dessus --- le reste du fichier (connector.py, imports, TABLE_TO_NODE_TYPE) ne change pas.

# packages/connectors/servicenow/mapper.py

# Remplace la fonction map_ci() ci-dessus --- le reste du fichier ne change pas

def map_ci(self, table: str, rec: dict) -\> Optional[CuzNode]:

node_type = TABLE_TO_NODE_TYPE.get(table)

if not node_type:

return None

# FIX-1 : distinguer un prestataire tiers d\'une application interne

# sur cmdb_ci_service, selon l\'attribut u_vendor_type du CI ServiceNow.

if table == \"cmdb_ci_service\" and rec.get(\"u_vendor_type\") == \"third_party\":

node_type = NodeType.THIRD_PARTY

name = rec.get(\"name\") or rec.get(\"sys_id\", \"unknown\")

last_seen = datetime.now(timezone.utc)

return CuzNode(

tenant_id=self.tenant_id,

node_type=node_type,

name=name,

external_id=rec.get(\"sys_id\"),

external_ids={\"servicenow\": rec.get(\"sys_id\", \"\")},

confidence_score=compute_confidence([\"servicenow\"]),

freshness_score=compute_freshness(node_type, last_seen),

sources=[\"servicenow\"],

last_seen=last_seen,

attributes={

\"operational_status\": rec.get(\"operational_status\"),

\"environment\": rec.get(\"environment\"),

\"sys_class_name\": rec.get(\"sys_class_name\"),

\"ip_address\": rec.get(\"ip_address\"),

\"os\": rec.get(\"os\"),

\"exit_plan_status\": rec.get(\"exit_plan_status\"),

\"vendor\": rec.get(\"vendor\"),

\"support_group\": rec.get(\"support_group\"),

\"u_vendor_type\": rec.get(\"u_vendor_type\"),

},

tags={

\"source\": \"servicenow\",

\"cmdb_table\": table,

},

)

Tests à ajouter --- tests/test_servicenow.py

def test_mapper_third_party_vendor():

mapper = ServiceNowMapper(TENANT)

rec = {\"sys_id\": \"tp001\", \"name\": \"Acme-Payment-SaaS\",

\"u_vendor_type\": \"third_party\", \"exit_plan_status\": None}

node = mapper.map_ci(\"cmdb_ci_service\", rec)

assert node.node_type == NodeType.THIRD_PARTY

def test_mapper_service_without_vendor_type_stays_application():

mapper = ServiceNowMapper(TENANT)

rec = {\"sys_id\": \"svc001\", \"name\": \"internal-billing\"}

node = mapper.map_ci(\"cmdb_ci_service\", rec)

assert node.node_type == NodeType.APPLICATION

Note pour AC.5 (Guide AcmeCorp) : le CI Acme-Payment-SaaS créé dans la PDI doit désormais porter u_vendor_type: \"third_party\" pour que ce correctif produise l\'effet attendu. Si le CI existe déjà sans cet attribut, le mettre à jour via l\'API ServiceNow avant de relancer un scan.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critère de sortie P1.1 (complément V3)** pytest packages/connectors/servicenow/tests/ -v → les 2 nouveaux tests passent en plus des tests existants.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------

P1.5 --- Pipeline d\'ingestion + Normalizer

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ Statut V3** Section réécrite par rapport à la v1.0 : le correctif FIX-2 (écriture des arêtes) est intégré directement dans le Normalizer, plutôt que présenté comme un patch séparé. producer.py et consumer.py restent identiques à la v1.0 sauf l\'adaptation signalée plus bas.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Objectif :** Implémenter le flux complet connecteur → Redpanda → Normalizer → NormalizedEvent(s). Garantir l\'idempotence, mettre en place une Dead Letter Queue, et --- nouveauté V3 --- transporter aussi les arêtes (CuzEdge), pas seulement les nœuds.

Fichiers à créer

-   packages/ingestion/__init__.py

-   packages/ingestion/producer.py

-   packages/ingestion/consumer.py

-   packages/ingestion/normalizer.py

-   packages/ingestion/tests/__init__.py

-   packages/ingestion/tests/test_pipeline.py

producer.py --- inchangé de la v1.0

# packages/ingestion/producer.py

import json

from datetime import datetime

from confluent_kafka import Producer

from packages.core.models.events import RawEvent

class EventProducer:

def __init__(self, bootstrap_servers: str = \"localhost:19092\"):

self.producer = Producer({\"bootstrap.servers\": bootstrap_servers})

def _get_topic(self, tenant_id: str) -\> str:

return f\"cuz.raw.{tenant_id}\"

def publish(self, event: RawEvent) -\> None:

topic = self._get_topic(event.tenant_id)

payload = event.model_dump_json().encode(\"utf-8\")

self.producer.produce(

topic=topic,

key=event.event_id.encode(\"utf-8\"),

value=payload,

)

self.producer.poll(0)

def flush(self) -\> None:

self.producer.flush(timeout=10)

core/models/events.py --- NormalizedEvent, complété (FIX-2)

Un seul champ est ajouté au modèle existant --- aucun champ n\'est retiré ni renommé.

# packages/core/models/events.py

class NormalizedEvent(BaseModel):

event_id: str

raw_event_id: str

tenant_id: str

source: str

event_type: EventType

timestamp: datetime

node: Optional[CuzNode] = None # inchangé

edge: Optional[CuzEdge] = None # NOUVEAU (V3) --- permet de transporter une arête

schema_version: str = \"1.0\"

normalizer.py --- normalize() produit des nœuds ET des arêtes

Contrairement à la v1.0 (qui ne retournait qu\'un Optional[NormalizedEvent] porteur d\'un seul nœud), cette version retourne une liste : un repo Gitea avec dépendances produit 1 événement nœud (le repo) + N événements nœud (les dépendances) + N événements arête (DEPENDS_ON, réutilisant map_repo_dependency_edge() déjà présent dans GiteaMapper mais jusqu\'ici jamais appelé).

# packages/ingestion/normalizer.py

import uuid

from datetime import datetime, timezone

from typing import Optional

from packages.core.models.events import RawEvent, NormalizedEvent, EventType

from packages.core.models.node import CuzNode

from packages.core.models.edge import CuzEdge

from packages.connectors.servicenow.mapper import ServiceNowMapper

from packages.connectors.minio.mapper import MinIOMapper

from packages.connectors.entra_id.mapper import EntraIDMapper

from packages.connectors.gitea.mapper import GiteaMapper

class Normalizer:

def __init__(self):

self._mappers: dict = {}

self._repo_node_cache: dict = {} # (tenant_id, repo_external_id) -\> CuzNode

def _get_mapper(self, source: str, tenant_id: str):

key = (source, tenant_id)

if key not in self._mappers:

if source == \"servicenow\":

self._mappers[key] = ServiceNowMapper(tenant_id)

elif source == \"minio\":

self._mappers[key] = MinIOMapper(tenant_id)

elif source == \"entra_id\":

self._mappers[key] = EntraIDMapper(tenant_id)

elif source == \"gitea\":

self._mappers[key] = GiteaMapper(tenant_id)

return self._mappers.get(key)

def normalize(self, raw: RawEvent) -\> list[NormalizedEvent]:

\"\"\"Retourne une LISTE de NormalizedEvent (peut être vide) : un repo

Gitea peut produire 1 événement nœud + N événements arête (une par

dépendance). Changement de signature par rapport à la v1.0, qui

retournait Optional[NormalizedEvent].\"\"\"

mapper = self._get_mapper(raw.source, raw.tenant_id)

if not mapper:

return []

results: list[NormalizedEvent] = []

if raw.source == \"servicenow\":

node = mapper.map_ci(raw.raw_data[\"table\"], raw.raw_data[\"record\"])

if node:

results.append(self._wrap(raw, node=node))

elif raw.source == \"minio\":

node = mapper.map_bucket(raw.raw_data)

results.append(self._wrap(raw, node=node))

elif raw.source == \"entra_id\":

obj_type = raw.raw_data.get(\"object_type\")

if obj_type == \"user\":

node = mapper.map_user(raw.raw_data[\"record\"])

results.append(self._wrap(raw, node=node))

elif obj_type == \"service_principal\":

node = mapper.map_service_principal(raw.raw_data[\"record\"])

results.append(self._wrap(raw, node=node))

elif raw.source == \"gitea\":

obj_type = raw.raw_data.get(\"object_type\")

if obj_type == \"repository\":

repo_node = mapper.map_repo(raw.raw_data)

results.append(self._wrap(raw, node=repo_node))

cache_key = (raw.tenant_id, raw.raw_data[\"repo_id\"])

self._repo_node_cache[cache_key] = repo_node

# FIX-2 : produire un événement nœud + un événement arête

# par dépendance, en réutilisant map_repo_dependency_edge()

# déjà présent dans GiteaMapper (jusqu\'ici jamais appelé).

for dep in raw.raw_data.get(\"dependencies\", []):

dep_node = mapper.map_dependency(dep)

results.append(self._wrap(raw, node=dep_node))

edge = mapper.map_repo_dependency_edge(repo_node, dep_node)

results.append(self._wrap(raw, edge=edge))

return results

def _wrap(self, raw: RawEvent, node=None, edge=None) -\> NormalizedEvent:

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

consumer.py --- adapté à la nouvelle signature de normalize()

# packages/ingestion/consumer.py

import json

import logging

from confluent_kafka import Consumer, KafkaError, Producer

from packages.core.models.events import RawEvent

from packages.ingestion.normalizer import Normalizer

logger = logging.getLogger(__name__)

SEEN_EVENT_IDS: set = set() # en mémoire --- Redis en prod

class PipelineConsumer:

def __init__(

self,

bootstrap_servers: str = \"localhost:19092\",

group_id: str = \"cuz-ingestion\",

max_retries: int = 3,

):

self.normalizer = Normalizer()

self.max_retries = max_retries

self.consumer = Consumer({

\"bootstrap.servers\": bootstrap_servers,

\"group.id\": group_id,

\"auto.offset.reset\": \"earliest\",

\"enable.auto.commit\": False,

})

self.dlq_producer = Producer({\"bootstrap.servers\": bootstrap_servers})

def _get_dlq_topic(self, tenant_id: str) -\> str:

return f\"cuz.graph.mutations.{tenant_id}.dlq\"

def _to_dlq(self, tenant_id: str, raw_bytes: bytes, reason: str) -\> None:

topic = self._get_dlq_topic(tenant_id)

self.dlq_producer.produce(topic, value=raw_bytes,

headers=[(\"reason\", reason.encode())])

self.dlq_producer.poll(0)

def run(self, tenant_id: str, on_normalized=None) -\> None:

topic = f\"cuz.raw.{tenant_id}\"

self.consumer.subscribe([topic])

try:

while True:

msg = self.consumer.poll(1.0)

if msg is None:

continue

if msg.error():

if msg.error().code() != KafkaError._PARTITION_EOF:

logger.error(\"Kafka error: %s\", msg.error())

continue

raw_bytes = msg.value()

try:

raw = RawEvent.model_validate_json(raw_bytes.decode())

except Exception as e:

self._to_dlq(tenant_id, raw_bytes, f\"parse_error:{e}\")

self.consumer.commit(message=msg)

continue

# Idempotence

if raw.event_id in SEEN_EVENT_IDS:

self.consumer.commit(message=msg)

continue

SEEN_EVENT_IDS.add(raw.event_id)

retries = 0

while retries \< self.max_retries:

try:

# V3 : normalize() retourne une LISTE, on itère dessus

# (v1.0 testait `if normalized`, ne s\'applique plus)

normalized_list = self.normalizer.normalize(raw)

if on_normalized:

for normalized in normalized_list:

on_normalized(normalized)

break

except Exception as e:

retries += 1

if retries \>= self.max_retries:

self._to_dlq(tenant_id, raw_bytes, f\"normalize_error:{e}\")

self.consumer.commit(message=msg)

finally:

self.consumer.close()

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION** Différence avec la v1.0 : normalize() retournait un Optional[NormalizedEvent], elle retourne désormais list[NormalizedEvent] (peut être vide). C\'est le changement le plus structurant de ce correctif --- s\'assurer qu\'aucun autre appelant de normalize() (dans P1.7 notamment) ne teste encore `if normalized`.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

tests/test_pipeline.py

# packages/ingestion/tests/test_pipeline.py

import uuid

from datetime import datetime, timezone

from packages.core.models.events import RawEvent, EventType

from packages.ingestion.normalizer import Normalizer

def make_raw(source: str, raw_data: dict, tenant: str = \"acmecorp\") -\> RawEvent:

return RawEvent(

event_id=str(uuid.uuid4()),

tenant_id=tenant,

source=source,

event_type=EventType.NODE_CREATED,

timestamp=datetime.now(timezone.utc),

raw_data=raw_data,

)

def test_normalize_servicenow_server():

n = Normalizer()

raw = make_raw(\"servicenow\", {\"table\": \"cmdb_ci_server\",

\"record\": {\"sys_id\": \"x1\", \"name\": \"srv-prod-01\"}})

results = n.normalize(raw)

assert len(results) == 1

assert results[0].node.node_type.value == \"SERVER\"

def test_normalize_minio_bucket():

n = Normalizer()

raw = make_raw(\"minio\", {\"bucket_name\": \"acmecorp-public\",

\"is_public\": True, \"objects\": [], \"tags\": {},

\"endpoint\": \"localhost:9000\"})

results = n.normalize(raw)

assert results[0].node.attributes[\"is_public\"] is True

def test_normalize_entra_user():

n = Normalizer()

raw = make_raw(\"entra_id\", {\"object_type\": \"user\", \"record\": {

\"id\": \"uid-001\", \"displayName\": \"Djana Dev\",

\"userPrincipalName\": \"djana.dev@acmecorp.onmicrosoft.com\",

\"accountEnabled\": True, \"has_mfa\": False,

\"mfa_methods\": [], \"createdDateTime\": \"2024-01-01T00:00:00Z\"

}})

results = n.normalize(raw)

assert results[0].node.attributes[\"has_mfa\"] is False

def test_normalize_gitea_repo_produces_node_and_edges():

n = Normalizer()

raw = make_raw(\"gitea\", {\"object_type\": \"repository\", \"repo_id\": \"42\",

\"name\": \"backend\", \"full_name\": \"acmecorp/backend\",

\"owner\": \"acmecorp\", \"private\": True,

\"default_branch\": \"main\",

\"dependencies\": [{\"name\": \"qs\", \"version\": \"6.5.2\",

\"ecosystem\": \"npm\"}]})

results = n.normalize(raw)

# 1 événement repo + 1 événement dépendance + 1 événement arête

assert len(results) == 3

node_events = [r for r in results if r.node is not None]

edge_events = [r for r in results if r.edge is not None]

assert len(node_events) == 2

assert len(edge_events) == 1

assert edge_events[0].edge.edge_type.value == \"DEPENDS_ON\"

def test_idempotence_same_event_id():

\"\"\"Le même event_id ne doit produire qu\'un seul traitement.\"\"\"

from packages.ingestion.consumer import SEEN_EVENT_IDS

event_id = str(uuid.uuid4())

SEEN_EVENT_IDS.add(event_id)

assert event_id in SEEN_EVENT_IDS

def test_normalize_unknown_source_returns_empty_list():

n = Normalizer()

raw = make_raw(\"unknown_source\", {\"foo\": \"bar\"})

results = n.normalize(raw)

assert results == []

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **💡 Installation** pip install confluent-kafka. Créer les topics Redpanda avant de tester le consumer : docker exec cuz-redpanda rpk topic create cuz.raw.acmecorp cuz.normalized.acmecorp cuz.graph.mutations.acmecorp cuz.graph.mutations.acmecorp.dlq --partitions 6 --replicas 1

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critères de sortie P1.5** pytest packages/ingestion/tests/ -v → tous verts, y compris test_normalize_gitea_repo_produces_node_and_edges (nouveau V3). Pipeline bout-en-bout fonctionnel. Idempotence : 100 événements dupliqués → 0 doublon. DLQ visible dans Redpanda. Un RawEvent Gitea avec N dépendances produit exactement 1+2N NormalizedEvent.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.6 --- Entity Resolution déterministe

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ Statut V3** resolver.py et merger.py (matching sur identifiants forts) sont inchangés de la v1.0. Un complément est ajouté en fin de section : la résolution d\'une arête OWNS entre un USER (Entra ID) et un REPOSITORY (Gitea), nécessaire à ATTACK-PATH-001-PARTIAL (§P1.8) et absente de la v1.0 comme du code actuel.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Objectif :** Éviter les doublons lors du merge multi-sources en matchant sur les identifiants forts (sys_id, object_id, repo_id, bucket_name). Recalculer confidence et freshness après fusion.

Fichiers à créer

-   packages/entity-resolution/__init__.py

-   packages/entity-resolution/resolver.py

-   packages/entity-resolution/merger.py

-   packages/entity-resolution/tests/__init__.py

-   packages/entity-resolution/tests/test_entity_resolution.py

-   packages/entity-resolution/owner_linker.py --- NOUVEAU (V3)

resolver.py

# packages/entity-resolution/resolver.py

from typing import Dict, List, Optional, Tuple

from packages.core.models.node import CuzNode

STRONG_ID_KEYS = {

\"servicenow\": \"servicenow\",

\"minio\": \"minio\",

\"entra_id\": \"entra_id\",

\"gitea\": \"gitea\",

}

class DeterministicResolver:

\"\"\"Match sur identifiants forts --- doublons \< 10% garantis.\"\"\"

def __init__(self):

# index: (tenant_id, source, external_id) -\> CuzNode.id

self._index: Dict[Tuple[str, str, str], str] = {}

# stockage: node.id -\> CuzNode

self._store: Dict[str, CuzNode] = {}

def _get_key(self, node: CuzNode) -\> Optional[Tuple[str, str, str]]:

for source, ext_id in node.external_ids.items():

if ext_id and source in STRONG_ID_KEYS:

return (node.tenant_id, source, ext_id)

return None

def resolve(self, node: CuzNode) -\> Tuple[Optional[str], bool]:

\"\"\"Retourne (existing_node_id \| None, is_duplicate).\"\"\"

key = self._get_key(node)

if key and key in self._index:

return self._index[key], True

return None, False

def register(self, node: CuzNode) -\> None:

\"\"\"Enregistrer un nœud dans l\'index.\"\"\"

self._store[node.id] = node

key = self._get_key(node)

if key:

self._index[key] = node.id

def get(self, node_id: str) -\> Optional[CuzNode]:

return self._store.get(node_id)

merger.py

# packages/entity-resolution/merger.py

from datetime import datetime, timezone

from typing import List

from packages.core.models.node import CuzNode

from packages.core.scoring import compute_confidence, compute_freshness

from packages.entity_resolution.resolver import DeterministicResolver

class NodeMerger:

def __init__(self, resolver: DeterministicResolver):

self.resolver = resolver

def merge_or_create(self, incoming: CuzNode) -\> CuzNode:

existing_id, is_dup = self.resolver.resolve(incoming)

if not is_dup:

self.resolver.register(incoming)

return incoming

existing = self.resolver.get(existing_id)

merged = self._merge(existing, incoming)

self.resolver._store[existing_id] = merged

return merged

def _merge(self, existing: CuzNode, incoming: CuzNode) -\> CuzNode:

\"\"\"Newest wins pour les attributs. Union pour sources/external_ids.\"\"\"

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

tests/test_entity_resolution.py

# packages/entity-resolution/tests/test_entity_resolution.py

import pytest

from datetime import datetime, timezone

from packages.core.models.node import CuzNode

from packages.core.models.enums import NodeType

from packages.entity_resolution.resolver import DeterministicResolver

from packages.entity_resolution.merger import NodeMerger

def make_node(name: str, source: str, ext_id: str, tenant: str = \"acmecorp\") -\> CuzNode:

return CuzNode(

tenant_id=tenant,

node_type=NodeType.SERVER,

name=name,

external_id=ext_id,

external_ids={source: ext_id},

confidence_score=0.8,

freshness_score=0.9,

sources=[source],

last_seen=datetime.now(timezone.utc),

)

def test_resolver_no_duplicate_different_ids():

r = DeterministicResolver()

n1 = make_node(\"srv-01\", \"servicenow\", \"sys_id_001\")

n2 = make_node(\"srv-02\", \"servicenow\", \"sys_id_002\")

r.register(n1)

existing_id, is_dup = r.resolve(n2)

assert not is_dup

def test_resolver_detects_duplicate_same_id():

r = DeterministicResolver()

n1 = make_node(\"srv-01\", \"servicenow\", \"sys_id_001\")

r.register(n1)

n2 = make_node(\"srv-01-updated\", \"servicenow\", \"sys_id_001\")

existing_id, is_dup = r.resolve(n2)

assert is_dup

assert existing_id == n1.id

def test_merger_merges_multi_source():

r = DeterministicResolver()

m = NodeMerger(r)

n1 = make_node(\"srv-01\", \"servicenow\", \"sys_id_001\")

n2 = CuzNode(

tenant_id=\"acmecorp\",

node_type=NodeType.SERVER,

name=\"srv-01\",

external_id=\"sys_id_001\",

external_ids={\"servicenow\": \"sys_id_001\", \"entra_id\": \"entra_001\"},

confidence_score=0.75,

freshness_score=0.85,

sources=[\"entra_id\"],

last_seen=datetime.now(timezone.utc),

)

merged1 = m.merge_or_create(n1)

merged2 = m.merge_or_create(n2)

assert merged2.id == merged1.id

assert \"entra_id\" in merged2.sources

assert \"servicenow\" in merged2.sources

def test_merger_confidence_increases_with_sources():

r = DeterministicResolver()

m = NodeMerger(r)

n1 = make_node(\"bucket-x\", \"minio\", \"bucket-x\")

n2 = CuzNode(

tenant_id=\"acmecorp\",

node_type=NodeType.STORAGE,

name=\"bucket-x\",

external_id=\"bucket-x\",

external_ids={\"minio\": \"bucket-x\", \"gitea\": \"bucket-x\"},

confidence_score=0.9,

freshness_score=0.9,

sources=[\"gitea\"],

last_seen=datetime.now(timezone.utc),

)

m.merge_or_create(n1)

merged = m.merge_or_create(n2)

assert merged.confidence_score \>= 0.8

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critères de sortie P1.6 (base v1.0)** pytest packages/entity-resolution/tests/ -v → tous verts. Taux de doublons \< 10% sur identifiants forts. Aucune fusion erronée entre tenants différents. confidence_score augmente après merge multi-sources.

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Complément V3 --- owner_linker.py : résoudre l\'arête OWNS (USER → REPOSITORY)

Ce point n\'était pas identifié comme bloquant dans le guide v1.0 : ATTACK-PATH-001-PARTIAL (§P1.8) a besoin d\'une arête OWNS entre un USER et un REPOSITORY, que ni le connecteur Entra ID ni le connecteur Gitea ne produisent. Le repo Gitea porte déjà l\'identité de son propriétaire dans attributes[\"owner\"] (mapper.py, map_repo()) sous forme de nom d\'utilisateur Gitea --- c\'est une chaîne de caractères, pas une référence à un CuzNode. Ce nom coïncide, sur AcmeCorp, avec la partie locale de l\'UPN Entra ID (djana.dev pour l\'utilisateur djana.dev@acmecorp.onmicrosoft.com --- voir AC.3 et AC.4). C\'est une convention de nommage propre au jeu de données AcmeCorp, pas une garantie générale : elle est documentée comme telle plutôt que supposée universelle.

# packages/entity-resolution/owner_linker.py

\"\"\"Résout l\'arête OWNS entre un USER (Entra ID) et un REPOSITORY (Gitea).

Aucun connecteur ne produit cette arête directement : le repo Gitea ne

connaît son propriétaire que par un nom d\'utilisateur Gitea (attributes

[\'owner\']), pas par une référence à un CuzNode USER. La résolution se fait

donc ici, après que les deux nœuds ont été vus par l\'entity resolution,

sur la convention AcmeCorp : le nom d\'utilisateur Gitea correspond à la

partie locale de l\'UPN Entra ID (djana.dev \<-\> djana.dev@acmecorp\...).

Limite assumée : si cette convention de nommage ne tient pas chez un futur

client (Stellantis ou autre), ce linker doit être adapté ou remplacé par

un identifiant explicite côté Gitea (ex: mapping manuel owner -\> UPN).

Ce n\'est pas un mécanisme d\'entity resolution probabiliste (réservé à

Splink en P2.5) : c\'est un rapprochement déterministe sur une convention

documentée, dans le même esprit que le reste de P1.6.\"\"\"

from typing import Optional

from packages.core.models.node import CuzNode

from packages.core.models.edge import CuzEdge

from packages.core.models.enums import EdgeType

from packages.core.scoring import compute_confidence, compute_freshness

from datetime import datetime, timezone

class OwnerLinker:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

# index construit au fil des nœuds USER résolus : upn_local_part -\> CuzNode

self._users_by_local_part: dict[str, CuzNode] = {}

def register_user(self, user_node: CuzNode) -\> None:

\"\"\"À appeler pour chaque USER une fois résolu par le NodeMerger (P1.6).\"\"\"

upn = user_node.attributes.get(\"upn\")

if not upn or \"@\" not in upn:

return

local_part = upn.split(\"@\")[0].lower()

self._users_by_local_part[local_part] = user_node

def resolve_owns_edge(self, repo_node: CuzNode) -\> Optional[CuzEdge]:

\"\"\"Retourne une CuzEdge OWNS (user -\> repo) si le owner du repo

correspond à un USER déjà enregistré, None sinon (ne pas fabriquer

un lien sur une correspondance incertaine).\"\"\"

owner = repo_node.attributes.get(\"owner\")

if not owner:

return None

user_node = self._users_by_local_part.get(owner.lower())

if not user_node:

return None

last_seen = datetime.now(timezone.utc)

return CuzEdge(

tenant_id=self.tenant_id,

edge_type=EdgeType.OWNS,

source_id=user_node.id,

target_id=repo_node.id,

confidence_score=compute_confidence([\"gitea\", \"entra_id\"]),

freshness_score=compute_freshness(repo_node.node_type, last_seen),

sources=[\"gitea\", \"entra_id\"],

last_seen=last_seen,

attributes={\"resolution_method\": \"owner_upn_local_part_match\"},

)

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION** EdgeType.OWNS n\'existe pas dans l\'enum actuel (packages/core/models/enums.py ne contient, en plus des types du guide v1.0, que CONTRACT côté NodeType et GOVERNED_BY/COVERS côté EdgeType). L\'ajouter comme valeur supplémentaire : OWNS = \"OWNS\" --- ajout pur, aucune valeur existante n\'est renommée ni retirée.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Où appeler OwnerLinker --- intégration au flux P1.5/P1.7

OwnerLinker vit à côté du NodeMerger, pas à l\'intérieur : le GraphWriter (P1.7) appelle register_user() pour chaque USER upserté, puis resolve_owns_edge() pour chaque REPOSITORY upserté, et upserte l\'arête OWNS obtenue exactement comme les autres arêtes (même UPSERT_EDGE_CYPHER que pour DEPENDS_ON, voir §P1.7). L\'ordre importe : un repo peut être vu avant son propriétaire (le scan initial ne garantit pas d\'ordre entre connecteurs Entra ID et Gitea) ; resolve_owns_edge() retournant None dans ce cas, il faut relancer la résolution après le scan complet plutôt qu\'une seule fois en flux --- un job de réconciliation périodique (P1.14, inchangé) est le point naturel pour ce rattrapage, en plus du chemin temps réel.

def test_owner_linker_resolves_known_convention():

linker = OwnerLinker(\"acmecorp\")

user = CuzNode(tenant_id=\"acmecorp\", node_type=NodeType.USER, name=\"Djana Dev\",

external_id=\"uid-001\", confidence_score=0.9, freshness_score=0.9,

sources=[\"entra_id\"], last_seen=datetime.now(timezone.utc),

attributes={\"upn\": \"djana.dev@acmecorp.onmicrosoft.com\"})

repo = CuzNode(tenant_id=\"acmecorp\", node_type=NodeType.REPOSITORY, name=\"backend\",

external_id=\"42\", confidence_score=0.9, freshness_score=0.9,

sources=[\"gitea\"], last_seen=datetime.now(timezone.utc),

attributes={\"owner\": \"djana.dev\"})

linker.register_user(user)

edge = linker.resolve_owns_edge(repo)

assert edge is not None

assert edge.edge_type == EdgeType.OWNS

def test_owner_linker_returns_none_when_owner_unknown():

linker = OwnerLinker(\"acmecorp\")

repo = CuzNode(tenant_id=\"acmecorp\", node_type=NodeType.REPOSITORY, name=\"orphan-repo\",

external_id=\"99\", confidence_score=0.9, freshness_score=0.9,

sources=[\"gitea\"], last_seen=datetime.now(timezone.utc),

attributes={\"owner\": \"unknown-user\"})

assert linker.resolve_owns_edge(repo) is None

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critère de sortie P1.6 (complément V3)** EdgeType.OWNS ajouté à l\'enum. OwnerLinker résout au moins l\'arête djana.dev → backend sur AcmeCorp après un scan complet. MATCH ()-[r:CUZ_EDGE {tenant_id:\'acmecorp\', edge_type:\'OWNS\'}]-\>() RETURN count(r) → ≥ 1. Un repo sans correspondance connue ne produit aucune arête erronée (test_owner_linker_returns_none_when_owner_unknown).

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.7 --- Graph Writer (upsert Neo4j)

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ Statut V3** client.py est inchangé de la v1.0. writer.py est réécrit pour consommer aussi les arêtes (event.edge, produites depuis P1.5) et pour promouvoir certains attributs en propriétés Neo4j natives, condition nécessaire pour que les règles Cypher de P1.8 filtrent correctement.

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Objectif :** Consommer les NormalizedEvent(s) et upsert les nœuds ET les arêtes dans Neo4j via MERGE. Publier les mutations confirmées sur cuz.graph.mutations.{tenant_id}.

Fichiers à créer

-   packages/graph/writer.py

-   packages/graph/client.py

-   packages/graph/tests/test_graph_writer.py

client.py --- inchangé de la v1.0

# packages/graph/client.py

import os

from neo4j import GraphDatabase, Driver

from typing import Optional

class Neo4jClient:

_driver: Optional[Driver] = None

\@classmethod

def get_driver(cls) -\> Driver:

if cls._driver is None:

uri = os.getenv(\"NEO4J_URI\", \"bolt://localhost:7687\")

user = os.getenv(\"NEO4J_USER\", \"neo4j\")

pwd = os.getenv(\"NEO4J_PASSWORD\", \"password\")

cls._driver = GraphDatabase.driver(uri, auth=(user, pwd))

return cls._driver

\@classmethod

def close(cls) -\> None:

if cls._driver:

cls._driver.close()

cls._driver = None

writer.py --- upsert des nœuds, des arêtes, et propriétés natives (FIX-2 + FIX-3)

# packages/graph/writer.py

import json

import logging

from datetime import datetime, timezone

from confluent_kafka import Consumer, Producer, KafkaError

from packages.core.models.events import NormalizedEvent

from packages.graph.client import Neo4jClient

from packages.entity_resolution.resolver import DeterministicResolver

from packages.entity_resolution.merger import NodeMerger

from packages.entity_resolution.owner_linker import OwnerLinker # NOUVEAU (V3, P1.6)

logger = logging.getLogger(__name__)

# FIX-3 : ces clés, quand présentes dans attributes, sont recopiées

# comme propriétés top-level du nœud Neo4j, pour un filtrage Cypher

# natif (n.has_mfa = false) au lieu d\'un CONTAINS fragile sur le JSON

# (json.dumps ajoute un espace après \':\', ce qui casse tout CONTAINS).

NATIVE_PROMOTED_KEYS = [

\"has_mfa\", \"is_public\", \"privileged\", \"run_as_root\",

\"contains_pii\", \"exit_plan_status\", \"criticality\", \"owner\",

\"account_enabled\", \"package_name\",

]

UPSERT_NODE_CYPHER = \"\"\"

MERGE (n:CuzNode {tenant_id: \$tenant_id, external_id: \$external_id})

ON CREATE SET

n.id = \$id,

n.node_type = \$node_type,

n.name = \$name,

n.confidence_score = \$confidence_score,

n.freshness_score = \$freshness_score,

n.sources = \$sources,

n.created_at = \$created_at,

n.updated_at = \$updated_at,

n.last_seen = \$last_seen,

n.attributes = \$attributes_json,

n.tags = \$tags_json,

n += \$native_attrs

ON MATCH SET

n.name = \$name,

n.confidence_score = \$confidence_score,

n.freshness_score = \$freshness_score,

n.sources = \$sources,

n.updated_at = \$updated_at,

n.last_seen = \$last_seen,

n.attributes = \$attributes_json,

n.tags = \$tags_json,

n += \$native_attrs

RETURN n.id as node_id

\"\"\"

# NOUVEAU (V3) : upsert d\'une arête. MATCH par tenant_id + id interne

# (les CuzEdge portent déjà des CuzNode.id générés par les mappers en

# source_id/target_id, pas des external_id).

UPSERT_EDGE_CYPHER = \"\"\"

MATCH (a:CuzNode {tenant_id: \$tenant_id, id: \$source_id})

MATCH (b:CuzNode {tenant_id: \$tenant_id, id: \$target_id})

MERGE (a)-[r:CUZ_EDGE {

tenant_id: \$tenant_id, edge_type: \$edge_type,

source_id: \$source_id, target_id: \$target_id

}]-\>(b)

ON CREATE SET

r.id = \$id,

r.confidence_score = \$confidence_score,

r.freshness_score = \$freshness_score,

r.sources = \$sources,

r.created_at = \$created_at,

r.last_seen = \$last_seen,

r.attributes = \$attributes_json

ON MATCH SET

r.confidence_score = \$confidence_score,

r.freshness_score = \$freshness_score,

r.sources = \$sources,

r.last_seen = \$last_seen,

r.attributes = \$attributes_json

RETURN r.id as edge_id

\"\"\"

class GraphWriter:

def __init__(self, bootstrap_servers: str = \"localhost:19092\"):

self.driver = Neo4jClient.get_driver()

self.resolver = DeterministicResolver()

self.merger = NodeMerger(self.resolver)

self.owner_linker = OwnerLinker(tenant_id=\"acmecorp\") # NOUVEAU (V3)

self.consumer = Consumer({

\"bootstrap.servers\": bootstrap_servers,

\"group.id\": \"cuz-graph-writer\",

\"auto.offset.reset\": \"earliest\",

\"enable.auto.commit\": False,

})

self.producer = Producer({\"bootstrap.servers\": bootstrap_servers})

def _native_attrs(self, attributes: dict) -\> dict:

\"\"\"FIX-3 : extrait les clés promues, en filtrant les None

(Neo4j n\'accepte pas de propriété nulle sur += ).\"\"\"

return {k: v for k, v in attributes.items()

if k in NATIVE_PROMOTED_KEYS and v is not None}

def _upsert_node(self, session, event: NormalizedEvent) -\> None:

node = self.merger.merge_or_create(event.node)

params = {

\"tenant_id\": node.tenant_id,

\"external_id\": node.external_id or node.id,

\"id\": node.id,

\"node_type\": node.node_type.value,

\"name\": node.name,

\"confidence_score\": node.confidence_score,

\"freshness_score\": node.freshness_score,

\"sources\": node.sources,

\"created_at\": node.created_at.isoformat(),

\"updated_at\": node.updated_at.isoformat(),

\"last_seen\": node.last_seen.isoformat(),

\"attributes_json\": json.dumps(node.attributes),

\"tags_json\": json.dumps(node.tags),

\"native_attrs\": self._native_attrs(node.attributes), # FIX-3

}

session.run(UPSERT_NODE_CYPHER, **params)

# NOUVEAU (V3, complète P1.6) : alimenter/consommer l\'OwnerLinker

# selon le type de nœud upserté.

if node.node_type.value == \"USER\":

self.owner_linker.register_user(node)

elif node.node_type.value == \"REPOSITORY\":

owns_edge = self.owner_linker.resolve_owns_edge(node)

if owns_edge:

self._upsert_edge(session, owns_edge)

def _upsert_edge(self, session, edge) -\> None:

\"\"\"NOUVEAU (V3). Appelé pour les arêtes produites par le Normalizer

(DEPENDS_ON) et pour l\'arête OWNS résolue par OwnerLinker.\"\"\"

params = {

\"tenant_id\": edge.tenant_id,

\"id\": edge.id,

\"edge_type\": edge.edge_type.value,

\"source_id\": edge.source_id,

\"target_id\": edge.target_id,

\"confidence_score\": edge.confidence_score,

\"freshness_score\": edge.freshness_score,

\"sources\": edge.sources,

\"created_at\": edge.created_at.isoformat(),

\"last_seen\": edge.last_seen.isoformat(),

\"attributes_json\": json.dumps(edge.attributes),

}

session.run(UPSERT_EDGE_CYPHER, **params)

def _publish_mutation(self, event: NormalizedEvent) -\> None:

topic = f\"cuz.graph.mutations.{event.tenant_id}\"

self.producer.produce(

topic=topic,

key=event.event_id.encode(),

value=event.model_dump_json().encode(),

)

self.producer.poll(0)

def run(self, tenant_id: str) -\> None:

self.consumer.subscribe([f\"cuz.normalized.{tenant_id}\"])

with self.driver.session() as session:

try:

while True:

msg = self.consumer.poll(1.0)

if msg is None:

continue

if msg.error():

continue

try:

event = NormalizedEvent.model_validate_json(msg.value().decode())

if event.node:

self._upsert_node(session, event)

self._publish_mutation(event)

if event.edge: # NOUVEAU (V3)

self._upsert_edge(session, event.edge)

self._publish_mutation(event)

except Exception as e:

logger.error(\"GraphWriter error: %s\", e)

self.consumer.commit(message=msg)

finally:

self.consumer.close()

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION** L\'upsert d\'arête suppose que les deux nœuds (source_id, target_id) existent déjà dans Neo4j au moment où l\'arête est traitée. Le Normalizer émet toujours le nœud repo, le nœud dépendance PUIS l\'arête (§P1.5), et Redpanda préserve l\'ordre au sein d\'une même partition (clé = tenant_id). Pour OWNS, l\'ordre entre connecteurs Entra ID et Gitea n\'est pas garanti au premier scan : un rattrapage par le job de réconciliation périodique (P1.14) reste nécessaire.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

tests/test_graph_writer.py

# packages/graph/tests/test_graph_writer.py

import pytest, json

from packages.graph.client import Neo4jClient

from packages.core.models.enums import NodeType

TENANT = \"acmecorp\"

def test_neo4j_connection():

driver = Neo4jClient.get_driver()

with driver.session() as session:

result = session.run(\"RETURN 1 AS ok\")

assert result.single()[\"ok\"] == 1

def test_node_count_after_ingestion():

\"\"\"Après P1.7 complet : \>200 nœuds AcmeCorp dans le graphe.\"\"\"

driver = Neo4jClient.get_driver()

with driver.session() as session:

result = session.run(

\"MATCH (n:CuzNode {tenant_id: \$t}) RETURN count(n) AS cnt\", t=TENANT

)

count = result.single()[\"cnt\"]

assert count \> 200

def test_edge_upsert_creates_relationship():

\"\"\"Après un cycle normalize -\> upsert, l\'arête DEPENDS_ON existe.\"\"\"

driver = Neo4jClient.get_driver()

with driver.session() as session:

result = session.run(

\"MATCH ()-[r:CUZ_EDGE {tenant_id:\$t, edge_type:\'DEPENDS_ON\'}]-\>() \"

\"RETURN count(r) AS cnt\", t=TENANT

)

assert result.single()[\"cnt\"] \> 0

def test_native_attrs_promoted_on_user_node():

\"\"\"has_mfa doit être filtrable comme propriété native, pas seulement

dans le blob attributes JSON.\"\"\"

driver = Neo4jClient.get_driver()

with driver.session() as session:

result = session.run(

\"MATCH (n:CuzNode {tenant_id:\$t, node_type:\'USER\'}) \"

\"WHERE n.has_mfa = false RETURN count(n) AS cnt\", t=TENANT

)

assert result.single()[\"cnt\"] \> 0

  ----------------------------------------------------------------------------------------------------------------------------------------
  **💡 Installation** pip install neo4j. S\'assurer que le schéma V001__initial_schema.cypher est appliqué avant la première écriture.

  ----------------------------------------------------------------------------------------------------------------------------------------

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critères de sortie P1.7** pytest packages/graph/tests/test_graph_writer.py -v → tous verts, y compris test_edge_upsert_creates_relationship et test_native_attrs_promoted_on_user_node. MATCH (n:CuzNode {tenant_id:\'acmecorp\'}) RETURN count(n) → \> 200 après scan complet. MATCH ()-[r:CUZ_EDGE {tenant_id:\'acmecorp\'}]-() RETURN r.edge_type, count(r) → DEPENDS_ON \> 0 et OWNS ≥ 1. Latence d\'écriture \< 500ms par événement.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚡ Point de synchronisation AC.9 --- Scan complet (après P1.7)** Le graphe writer est opérationnel. C\'est le moment de lancer le scan initial complet et de valider les 3 critères AC.9 : tous les connecteurs répondent 200, \> 200 nœuds dans Neo4j, ≥ 5 findings détectés dont ATTACK-PATH-001-PARTIAL (après P1.8).

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.8 --- Moteur de règles Cypher (20 règles)

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ℹ️ Statut V3** models.py (Finding) et runner.py sont inchangés de la v1.0. Les requêtes Cypher qui filtraient sur attributes CONTAINS sont réécrites sur propriétés natives (FIX-3). ATTACK-PATH-001 est redéfinie en version réalisable en Phase 1 (3 maillons, nouvel identifiant ATTACK-PATH-001-PARTIAL) ; la version à 5 maillons devient le critère de sortie de P2.1.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Objectif :** Runner Cypher déclenché par mutations. 20 règles produisant des Finding structurés. Valider ATTACK-PATH-001-PARTIAL sur AcmeCorp en Phase 1.

Fichiers à créer

-   packages/detection/__init__.py

-   packages/detection/runner.py

-   packages/detection/models.py

-   packages/detection/rules/__init__.py

-   packages/detection/rules/network.py

-   packages/detection/rules/iam.py

-   packages/detection/rules/attack_path.py

-   packages/detection/rules/dora.py

-   packages/detection/rules/cis.py

-   packages/detection/tests/test_detection.py

models.py --- Finding (inchangé de la v1.0)

# packages/detection/models.py

from datetime import datetime

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

import uuid

class Finding(BaseModel):

id: str = Field(default_factory=lambda: str(uuid.uuid4()))

tenant_id: str

rule_id: str

severity: str # CRITICAL \| HIGH \| MEDIUM \| LOW \| INFO

title: str

description: str

affected_nodes: List[str] # Liste de node.id

affected_node_names: List[str]

remediation_hint: str

status: str = \"open\" # open \| acknowledged \| false_positive \| resolved

created_at: datetime = Field(default_factory=datetime.utcnow)

updated_at: datetime = Field(default_factory=datetime.utcnow)

metadata: Dict[str, Any] = {}

Requêtes Cypher --- 20 règles (réécrites sur propriétés natives, FIX-3)

NET-001 --- Port SSH exposé depuis Internet (CRITICAL)

MATCH (n:CuzNode {tenant_id:\$tenant_id})

WHERE n.node_type IN [\'SERVER\',\'CONTAINER\',\'CLUSTER\']

AND n.port_22_exposed = true

AND n.is_public = true

RETURN n.id AS node_id, n.name AS node_name

IAM-001 --- Identité humaine sans MFA (HIGH)

MATCH (u:CuzNode {tenant_id:\$tenant_id, node_type:\'USER\'})

WHERE u.has_mfa = false

AND u.account_enabled = true

RETURN u.id AS node_id, u.name AS node_name

ATTACK-PATH-001-PARTIAL --- Chemin d\'attaque réalisable en Phase 1 (CRITICAL)

Le guide v1.0 fait transiter le chemin complet par HAS_ROLE → ALLOWS → DEPENDS_ON → AFFECTS → EXPOSES, cinq types d\'arêtes dont trois (HAS_ROLE, ALLOWS, EXPOSES) ne sont produits par aucun connecteur des Phases 0 et 1 --- le connecteur Kubernetes qui produirait EXPOSES est prévu en P2.1, pas avant. La version V3 retient les trois maillons réellement atteignables avec les connecteurs P1.1-P1.4 et l\'arête OWNS résolue en P1.6.

// ATTACK-PATH-001-PARTIAL --- critère de sortie Phase 1

MATCH (u:CuzNode {tenant_id:\$tenant_id, node_type:\'USER\'})

-[:CUZ_EDGE {edge_type:\'OWNS\'}]-\>(repo:CuzNode {node_type:\'REPOSITORY\'})

-[:CUZ_EDGE {edge_type:\'DEPENDS_ON\'}]-\>(dep:CuzNode {node_type:\'VULNERABILITY\'})

WHERE u.has_mfa = false

AND dep.package_name = \'qs\'

RETURN u.id, u.name, repo.id, repo.name, dep.id, dep.name

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠️ ATTENTION --- changement de trajectoire assumé** ATTACK-PATH-001 en 5 maillons complets (USER → REPOSITORY → VULNERABILITY → pod → STORAGE) dépend du connecteur Kubernetes (P2.1), qui n\'existe pas encore. Le critère de succès réalisable en Phase 1 est ATTACK-PATH-001-PARTIAL (3 maillons, ci-dessus). La version à 5 maillons devient le critère de sortie de P2.1, et non plus de P1 --- ce n\'est pas une simple correction de bug, c\'est un déplacement de critère documenté ici et dans le Plan de dev V3 (§3, §4, FIX-2).

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

OAUTH-LATERAL-001 --- Service Account OAuth vers données PII sans MFA (HIGH)

Règle inchangée dans son principe (dépend de HAS_ROLE/ALLOWS, non produites en Phase 1) : reste hors d\'atteinte tant que P2.1 n\'est pas livré, comme la version complète d\'ATTACK-PATH-001. Conservée ici pour mémoire, sans changement de requête.

MATCH (sa:CuzNode {tenant_id:\$tenant_id, node_type:\'SERVICE_ACCOUNT\'})

-[:CUZ_EDGE {edge_type:\'HAS_ROLE\'}]-\>(r:CuzNode)

-[:CUZ_EDGE {edge_type:\'ALLOWS\'}]-\>(bucket:CuzNode {node_type:\'STORAGE\'})

WHERE bucket.contains_pii = true

RETURN sa.id AS node_id, sa.name AS node_name, bucket.name AS bucket_name

STORAGE-PUBLIC-001 --- Bucket de stockage accessible publiquement (HIGH)

MATCH (b:CuzNode {tenant_id:\$tenant_id, node_type:\'STORAGE\'})

WHERE b.is_public = true

RETURN b.id AS node_id, b.name AS node_name

K8S-PRIV-001 --- Pod Kubernetes avec contexte privileged (HIGH)

MATCH (p:CuzNode {tenant_id:\$tenant_id, node_type:\'CONTAINER\'})

WHERE p.privileged = true OR p.run_as_root = true

RETURN p.id AS node_id, p.name AS node_name

IaC-DRIFT-001 --- Ressource présente en IaC absente de l\'infra réelle (MEDIUM)

Règle inchangée : ne dépend pas d\'attributs CONTAINS, donc non affectée par FIX-3.

MATCH (r:CuzNode {tenant_id:\$tenant_id})

WHERE r.tags CONTAINS \'\"iac_managed\":\"true\"\'

AND NOT EXISTS {

MATCH (real:CuzNode {tenant_id:\$tenant_id, name:r.name})

WHERE real.id \<\> r.id

}

RETURN r.id AS node_id, r.name AS node_name

DORA-THIRD-PARTY-001 --- Prestataire TIC critique sans plan de sortie (HIGH)

Débloquée par FIX-1 (§P1.1) : avant ce correctif, aucun nœud THIRD_PARTY n\'était jamais créé, donc cette règle ne matchait jamais, quelle que soit sa propre justesse.

MATCH (tp:CuzNode {tenant_id:\$tenant_id, node_type:\'THIRD_PARTY\'})

-[:CUZ_EDGE {edge_type:\'SUPPORTS\'}]-\>(bf:CuzNode)

WHERE tp.exit_plan_status IS NULL

RETURN tp.id AS node_id, tp.name AS node_name

Les 12 règles CIS restantes (CIS-001 à CIS-012, inchangées de la v1.0) couvrent : certificat TLS expiré, port critique exposé, service sans tag owner, nœud stale (freshness \< 0.2), groupe avec membre direct non via rôle, service account avec credential permanent, base de données sans backup configuré, ingress sans authentification, container image non signée, secret en clair dans les attributs, rôle admin permanent, API exposée sans rate limiting.

runner.py --- inchangé de la v1.0

# packages/detection/runner.py

import logging

from typing import List, Callable

from packages.detection.models import Finding

from packages.graph.client import Neo4jClient

from packages.detection.rules import network, iam, attack_path, dora, cis

logger = logging.getLogger(__name__)

ALL_RULE_MODULES = [network, iam, attack_path, dora, cis]

class DetectionRunner:

def __init__(self):

self.driver = Neo4jClient.get_driver()

def run_all(self, tenant_id: str) -\> List[Finding]:

findings = []

with self.driver.session() as session:

for module in ALL_RULE_MODULES:

for rule_fn in module.RULES:

try:

results = rule_fn(session, tenant_id)

findings.extend(results)

except Exception as e:

logger.error(\"Rule %s failed: %s\", rule_fn.__name__, e)

return findings

def run_on_mutation(self, tenant_id: str, affected_node_id: str) -\> List[Finding]:

\"\"\"Déclencher uniquement les règles sensibles à ce nœud.\"\"\"

return self.run_all(tenant_id) # Phase 2 : filtrage fin

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **💡 Vérification des arêtes** ATTACK-PATH-001-PARTIAL nécessite que les arêtes OWNS et DEPENDS_ON soient peuplées. Vérifier leur présence avec : MATCH ()-[r:CUZ_EDGE {tenant_id:\'acmecorp\'}]-() RETURN r.edge_type, count(r)

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critères de sortie P1.8** pytest packages/detection/tests/ -v → tous verts. ATTACK-PATH-001-PARTIAL détecté : djana.dev → backend → qs@6.5.2 (3 maillons). La version à 5 maillons est déplacée en critère de sortie P2.1. 20 règles actives, chaque Finding porte rule_id, severity, affected_nodes, remediation_hint. IAM-001 : djana.dev et svc-pipeline détectés. STORAGE-PUBLIC-001 : acmecorp-public détecté.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  ------------------------------------------------------------------------------------------------------
  **ℹ️ Statut V3** P1.9 à P1.15 ci-dessous reprennent le contenu de la v1.0 sans modification de fond.

  ------------------------------------------------------------------------------------------------------

P1.9 --- Moteur OPA/Rego (5 policies)

**Objectif :** 5 policies Rego pour les détections sur attributs (pas topologie). Client OPA Python. Findings OPA fusionnés avec findings Cypher.

Fichiers à créer

📄 packages/detection/rules/opa/human_no_mfa.rego

📄 packages/detection/rules/opa/bucket_unencrypted.rego

📄 packages/detection/rules/opa/port_exposed.rego

📄 packages/detection/rules/opa/cert_expired.rego

📄 packages/detection/rules/opa/service_no_owner.rego

📄 packages/detection/opa_client.py

human_no_mfa.rego

# packages/detection/rules/opa/human_no_mfa.rego

package cuz.iam

import future.keywords.if

deny[finding] if {

node := input.node

node.node_type == \"USER\"

node.attributes.has_mfa == false

node.attributes.account_enabled == true

finding := {

\"rule_id\": \"IAM-OPA-001\",

\"severity\": \"HIGH\",

\"title\": \"Identité humaine sans MFA (OPA)\",

\"description\": sprintf(\"L\'utilisateur %v n\'a aucune méthode MFA

enregistrée.\", [node.name]),

\"node_id\": node.id,

\"remediation_hint\": \"Activer l\'authentification multifacteur via

Entra ID \> Security \> MFA.\",

}

}

opa_client.py

# packages/detection/opa_client.py

import httpx

import os

from typing import List, Dict, Any

from packages.core.models.node import CuzNode

from packages.detection.models import Finding

import uuid

from datetime import datetime

OPA_URL = os.getenv(\"OPA_URL\", \"http://localhost:8181\")

POLICIES = [

(\"cuz/iam\", \"IAM-OPA-001\"),

(\"cuz/storage\", \"STORAGE-OPA-001\"),

(\"cuz/network\", \"NET-OPA-001\"),

(\"cuz/tls\", \"TLS-OPA-001\"),

(\"cuz/ownership\",\"OWN-OPA-001\"),

]

class OPAClient:

async def evaluate_node(self, node: CuzNode) -\> List[Finding]:

findings = []

node_dict = {

\"id\": node.id,

\"tenant_id\": node.tenant_id,

\"node_type\": node.node_type.value,

\"name\": node.name,

\"attributes\": node.attributes,

\"tags\": node.tags,

}

for policy_path, _ in POLICIES:

url = f\"{OPA_URL}/v1/data/{policy_path}/deny\"

try:

async with httpx.AsyncClient(timeout=5) as client:

r = await client.post(url, json={\"input\": {\"node\": node_dict}})

if r.status_code == 200:

results = r.json().get(\"result\", [])

for res in results:

findings.append(Finding(

id=str(uuid.uuid4()),

tenant_id=node.tenant_id,

rule_id=res.get(\"rule_id\", \"OPA-UNKNOWN\"),

severity=res.get(\"severity\", \"MEDIUM\"),

title=res.get(\"title\", \"OPA Finding\"),

description=res.get(\"description\", \"\"),

affected_nodes=[node.id],

affected_node_names=[node.name],

remediation_hint=res.get(\"remediation_hint\", \"\"),

created_at=datetime.utcnow(),

updated_at=datetime.utcnow(),

))

except Exception:

pass

return findings

**✅ Critères de sortie P1.9**

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  ✓ curl http://localhost:8181/v1/data/cuz/iam/deny -d \'{\"input\":{\"node\":{\"node_type\\ \":\"USER\",\"attributes\":{\"has_mfa\":false,\"account_enabled\":true },\"name\":\"djana.dev\",\"id\":\"x\",\"tenant_id\":\"acmecorp\"}}}\'

  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.10 --- API Findings

**Objectif :** Exposer les findings via REST avec filtres, pagination, acknowledge, false-positive, export CSV et statistiques.

Fichiers à créer

📄 services/api/routers/findings.py

📄 services/api/tests/test_findings_api.py

findings.py --- Router FastAPI

# services/api/routers/findings.py

import csv

import io

from datetime import datetime

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from fastapi.responses import StreamingResponse

from packages.detection.models import Finding

from packages.detection.runner import DetectionRunner

router = APIRouter(prefix=\"/api/v1/tenants/{tenant_id}/findings\",

tags=[\"findings\"])

runner = DetectionRunner()

_findings_store: dict = {} # En prod : PostgreSQL

def _get_findings(tenant_id: str) -\> List[Finding]:

if tenant_id not in _findings_store:

_findings_store[tenant_id] = runner.run_all(tenant_id)

return _findings_store[tenant_id]

\@router.get(\"/\", response_model=List[Finding])

async def list_findings(

tenant_id: str,

severity: Optional[str] = Query(None,

description=\"CRITICAL\|HIGH\|MEDIUM\|LOW\"),

rule_id: Optional[str] = Query(None),

status: Optional[str] = Query(None),

page: int = Query(1, ge=1),

size: int = Query(20, ge=1, le=100),

):

findings = _get_findings(tenant_id)

if severity:

findings = [f for f in findings if f.severity == severity.upper()]

if rule_id:

findings = [f for f in findings if f.rule_id == rule_id]

if status:

findings = [f for f in findings if f.status == status]

start = (page - 1) * size

return findings[start:start + size]

\@router.get(\"/stats\")

async def findings_stats(tenant_id: str):

findings = _get_findings(tenant_id)

by_severity = {}

for f in findings:

by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

return {

\"total\": len(findings),

\"by_severity\": by_severity,

\"open\": sum(1 for f in findings if f.status == \"open\"),

}

\@router.get(\"/export/csv\")

async def export_csv(tenant_id: str):

findings = _get_findings(tenant_id)

output = io.StringIO()

writer = csv.DictWriter(output, fieldnames=[

\"id\",\"rule_id\",\"severity\",\"title\",\"status\",

\"affected_node_names\",\"remediation_hint\",\"created_at\"

])

writer.writeheader()

for f in findings:

writer.writerow({

\"id\": f.id,

\"rule_id\": f.rule_id,

\"severity\": f.severity,

\"title\": f.title,

\"status\": f.status,

\"affected_node_names\": \",\".join(f.affected_node_names),

\"remediation_hint\": f.remediation_hint,

\"created_at\": f.created_at.isoformat(),

})

output.seek(0)

return StreamingResponse(

iter([output.getvalue()]),

media_type=\"text/csv\",

headers={\"Content-Disposition\": f\"attachment;

filename=findings_{tenant_id}.csv\"},

)

\@router.get(\"/{finding_id}\", response_model=Finding)

async def get_finding(tenant_id: str, finding_id: str):

findings = _get_findings(tenant_id)

f = next((f for f in findings if f.id == finding_id), None)

if not f:

raise HTTPException(status_code=404, detail=\"Finding not found\")

return f

\@router.post(\"/{finding_id}/acknowledge\")

async def acknowledge(tenant_id: str, finding_id: str,

justification: str = \"\", expiry: Optional[datetime] = None):

findings = _get_findings(tenant_id)

f = next((f for f in findings if f.id == finding_id), None)

if not f:

raise HTTPException(status_code=404, detail=\"Finding not found\")

f.status = \"acknowledged\"

f.updated_at = datetime.utcnow()

return {\"status\": \"acknowledged\", \"finding_id\": finding_id}

\@router.post(\"/{finding_id}/false-positive\")

async def false_positive(tenant_id: str, finding_id: str, reason: str

= \"\"):

findings = _get_findings(tenant_id)

f = next((f for f in findings if f.id == finding_id), None)

if not f:

raise HTTPException(status_code=404, detail=\"Finding not found\")

f.status = \"false_positive\"

f.updated_at = datetime.utcnow()

return {\"status\": \"false_positive\", \"finding_id\": finding_id}

**✅ Critères de sortie P1.10**

  -----------------------------------------------------------------------------------------------------
  ✓ curl http://localhost:8000/api/v1/tenants/acmecorp/findings/ -H \"Authorization: Bearer \$TOKEN\"

  -----------------------------------------------------------------------------------------------------

P1.11 --- Dashboard frontend MVP

**Objectif :** Page /dashboard avec KPIs, top 20 findings, timeline mutations, heatmap fraîcheur. Données AcmeCorp réelles. Chargement \< 3s.

Fichiers à créer

📄 frontend/src/app/dashboard/page.tsx

📄 frontend/src/app/dashboard/components/KpiCard.tsx

📄 frontend/src/app/dashboard/components/FindingsTable.tsx

📄 frontend/src/app/dashboard/components/FreshnessHeatmap.tsx

📄 frontend/src/lib/api.ts

page.tsx --- Dashboard principal

// frontend/src/app/dashboard/page.tsx

\"use client\";

import { useQuery } from \"@tanstack/react-query\";

import { KpiCard } from \"./components/KpiCard\";

import { FindingsTable } from \"./components/FindingsTable\";

import { FreshnessHeatmap } from \"./components/FreshnessHeatmap\";

import { fetchStats, fetchFindings } from \"@/lib/api\";

const TENANT = \"acmecorp\";

export default function DashboardPage() {

const { data: stats, isLoading: statsLoading } = useQuery({

queryKey: [\"stats\", TENANT],

queryFn: () =\> fetchStats(TENANT),

refetchInterval: 30000,

});

const { data: findings, isLoading: findingsLoading } = useQuery({

queryKey: [\"findings\", TENANT],

queryFn: () =\> fetchFindings(TENANT, { size: 20 }),

refetchInterval: 30000,

});

return (

\<main className=\"p-6 space-y-6\"\>

\<h1 className=\"text-2xl font-bold text-slate-800\"\>

CUz --- Tableau de bord AcmeCorp

\</h1\>

{/* KPIs */}

\<div className=\"grid grid-cols-4 gap-4\"\>

\<KpiCard label=\"Nœuds total\"

value={stats?.node_count ?? \"---\"}

loading={statsLoading} color=\"blue\" /\>

\<KpiCard label=\"CRITICAL\"

value={stats?.by_severity?.CRITICAL ?? 0}

loading={statsLoading} color=\"red\" /\>

\<KpiCard label=\"HIGH\"

value={stats?.by_severity?.HIGH ?? 0}

loading={statsLoading} color=\"orange\" /\>

\<KpiCard label=\"Score santé\"

value={stats?.health_score ? `\${Math.round(stats.health_score *

100)}%` : \"---\"}

loading={statsLoading} color=\"green\" /\>

\</div\>

{/* Top 20 findings */}

\<section\>

\<h2 className=\"text-lg font-semibold mb-3\"\>Top 20 findings

ouverts\</h2\>

\<FindingsTable findings={findings ?? []} loading={findingsLoading}

/\>

\</section\>

{/* Heatmap fraîcheur */}

\<section\>

\<h2 className=\"text-lg font-semibold mb-3\"\>Fraîcheur par

source\</h2\>

\<FreshnessHeatmap tenantId={TENANT} /\>

\</section\>

\</main\>

);

}

**✅ Critères de sortie P1.11**

  -----------------------------------------------------------------------
  ✓ npm run dev → http://localhost:3000/dashboard accessible

  -----------------------------------------------------------------------

P1.12 --- Vue graphe interactive

**Objectif :** Graphe AcmeCorp avec Cytoscape.js. Filtres par type/source/confiance. Chemins d\'attaque en rouge. Panel nœud au clic.

Fichiers à créer

📄 frontend/src/app/graph/page.tsx

📄 frontend/src/app/graph/components/GraphCanvas.tsx

📄 frontend/src/app/graph/components/NodePanel.tsx

📄 frontend/src/app/graph/components/GraphFilters.tsx

GraphCanvas.tsx (extrait clé)

// frontend/src/app/graph/components/GraphCanvas.tsx

\"use client\";

import CytoscapeComponent from \"react-cytoscapejs\";

import { useEffect, useRef, useState } from \"react\";

import { fetchGraphData } from \"@/lib/api\";

const ATTACK_PATH_RULE = \"ATTACK-PATH-001\";

const STYLE = [

{ selector: \"node\",

style: { \"background-color\": \"#2980B9\", label: \"data(name)\",

\"font-size\": \"10px\", color: \"#fff\", \"text-valign\": \"center\"

} },

{ selector: \"node[node_type=\'USER\']\",

style: { \"background-color\": \"#8E44AD\" } },

{ selector: \"node[node_type=\'STORAGE\']\",

style: { \"background-color\": \"#E67E22\" } },

{ selector: \"node.attack-path\",

style: { \"background-color\": \"#E74C3C\", \"border-width\": 3,

\"border-color\": \"#C0392B\" } },

{ selector: \"edge.attack-path\",

style: { \"line-color\": \"#E74C3C\", \"target-arrow-color\":

\"#E74C3C\",

width: 3 } },

{ selector: \"edge\",

style: { \"curve-style\": \"bezier\", \"target-arrow-shape\":

\"triangle\",

\"line-color\": \"#BDC3C7\", width: 1 } },

];

export function GraphCanvas({ tenantId, onNodeClick }) {

const [elements, setElements] = useState([]);

useEffect(() =\> {

fetchGraphData(tenantId).then(data =\> {

// Marquer les nœuds du chemin d\'attaque en rouge

const attackNodeIds = new Set(

data.findings

.filter(f =\> f.rule_id === ATTACK_PATH_RULE)

.flatMap(f =\> f.affected_nodes)

);

const nodes = data.nodes.map(n =\> ({

data: { id: n.id, name: n.name, node_type: n.node_type, \...n },

classes: attackNodeIds.has(n.id) ? \"attack-path\" : \"\",

}));

const edges = data.edges.map(e =\> ({

data: { id: e.id, source: e.source_id, target: e.target_id,

edge_type: e.edge_type },

classes: (attackNodeIds.has(e.source_id) &&

attackNodeIds.has(e.target_id)) ? \"attack-path\" : \"\",

}));

setElements([\...nodes, \...edges]);

});

}, [tenantId]);

return (

\<CytoscapeComponent

elements={elements}

style={{ width: \"100%\", height: \"600px\" }}

stylesheet={STYLE}

layout={{ name: \"cose\" }}

cy={cy =\> { cy.on(\"tap\", \"node\", e =\>

onNodeClick(e.target.data())); }}

/\>

);

}

**✅ Critères de sortie P1.12**

  -----------------------------------------------------------------------
  ✓ Graphe AcmeCorp rendu en \< 3s

  -----------------------------------------------------------------------

P1.13 --- Déploiement k3d AcmeCorp staging

**Objectif :** Déployer CUz dans le cluster k3d acmecorp avec NetworkPolicies, PodSecurityStandards, ResourceLimits et HPA.

Fichiers à créer

📄 infra/k8s/overlays/acmecorp/namespace.yaml

📄 infra/k8s/overlays/acmecorp/network-policy.yaml

📄 infra/k8s/overlays/acmecorp/resource-limits.yaml

📄 infra/k8s/overlays/acmecorp/hpa.yaml

📄 infra/k8s/overlays/acmecorp/kustomization.yaml

namespace.yaml

# infra/k8s/overlays/acmecorp/namespace.yaml

apiVersion: v1

kind: Namespace

metadata:

name: cuz-acmecorp

labels:

pod-security.kubernetes.io/enforce: restricted

pod-security.kubernetes.io/audit: restricted

pod-security.kubernetes.io/warn: restricted

network-policy.yaml

# infra/k8s/overlays/acmecorp/network-policy.yaml

apiVersion: networking.k8s.io/v1

kind: NetworkPolicy

metadata:

name: cuz-default-deny

namespace: cuz-acmecorp

spec:

podSelector: {}

policyTypes: [Ingress, Egress]

---

apiVersion: networking.k8s.io/v1

kind: NetworkPolicy

metadata:

name: cuz-api-ingress

namespace: cuz-acmecorp

spec:

podSelector:

matchLabels:

app: cuz-api

policyTypes: [Ingress]

ingress:

- ports:

- port: 8000

**✅ Critères de sortie P1.13**

  -----------------------------------------------------------------------
  ✓ kubectl apply -k infra/k8s/overlays/acmecorp/ → sans erreur

  -----------------------------------------------------------------------

P1.14 --- Jobs de réconciliation périodique

**Objectif :** CronJobs Kubernetes pour la réconciliation des sources et la gestion de la fraîcheur des nœuds.

Fichiers à créer

📄 infra/k8s/cronjobs/reconcile-servicenow.yaml

📄 infra/k8s/cronjobs/reconcile-entra-id.yaml

📄 infra/k8s/cronjobs/reconcile-git.yaml

📄 infra/k8s/cronjobs/freshness-decay.yaml

📄 infra/k8s/cronjobs/stale-detection.yaml

reconcile-servicenow.yaml

# infra/k8s/cronjobs/reconcile-servicenow.yaml

apiVersion: batch/v1

kind: CronJob

metadata:

name: reconcile-servicenow

namespace: cuz-acmecorp

spec:

schedule: \"0 2 * * *\" # Quotidien à 2h

jobTemplate:

spec:

template:

spec:

restartPolicy: OnFailure

containers:

- name: reconciler

image: cuz-ingestion-worker:latest

command: [\"python\", \"-m\", \"packages.ingestion.reconcile\",

\"--source\", \"servicenow\",

\"--tenant\", \"acmecorp\"]

envFrom:

- secretRef:

name: cuz-acmecorp-secrets

freshness-decay.yaml

# infra/k8s/cronjobs/freshness-decay.yaml

apiVersion: batch/v1

kind: CronJob

metadata:

name: freshness-decay

namespace: cuz-acmecorp

spec:

schedule: \"0 * * * *\" # Horaire

jobTemplate:

spec:

template:

spec:

restartPolicy: OnFailure

containers:

- name: decay-worker

image: cuz-detection-worker:latest

command: [\"python\", \"-m\", \"packages.detection.freshness_decay\",

\"--tenant\", \"acmecorp\"]

**✅ Critères de sortie P1.14**

  -----------------------------------------------------------------------
  ✓ kubectl get cronjobs -n cuz-acmecorp → 5 CronJobs listés

  -----------------------------------------------------------------------

P1.15 --- Export DORA --- Registre ICT

**Objectif :** Endpoint GET /exports/dora/ict-register → CSV format ESA depuis les nœuds ThirdParty et arêtes SUPPORTS→BusinessFunction. Testé sur Acme-Payment-SaaS.

Fichiers à créer

📄 services/api/routers/exports.py

exports.py

# services/api/routers/exports.py

import csv

import io

from fastapi import APIRouter

from fastapi.responses import StreamingResponse

from packages.graph.client import Neo4jClient

router = APIRouter(prefix=\"/api/v1/tenants/{tenant_id}/exports\",

tags=[\"exports\"])

DORA_CYPHER = \"\"\"

MATCH (tp:CuzNode {tenant_id: \$tenant_id, node_type:

\'THIRD_PARTY\'})

OPTIONAL MATCH (tp)-[r:CUZ_EDGE {edge_type:

\'SUPPORTS\'}]-\>(bf:CuzNode)

RETURN

tp.name AS provider_name,

tp.attributes AS provider_attrs,

bf.name AS function_name,

bf.attributes AS function_attrs,

r AS relationship

\"\"\"

\@router.get(\"/dora/ict-register\")

async def dora_ict_register(tenant_id: str):

driver = Neo4jClient.get_driver()

import json

rows = []

with driver.session() as session:

result = session.run(DORA_CYPHER, tenant_id=tenant_id)

for rec in result:

attrs = json.loads(rec[\"provider_attrs\"] or \"{}\")

rows.append({

\"provider_name\": rec[\"provider_name\"],

\"provider_type\": attrs.get(\"provider_type\", \"\"),

\"country\": attrs.get(\"country\", \"\"),

\"criticality\": attrs.get(\"criticality\", \"\"),

\"exit_plan_status\": attrs.get(\"exit_plan_status\", \"NOT_SET\"),

\"supported_function\": rec[\"function_name\"] or \"\",

\"contract_end_date\": attrs.get(\"contract_end_date\", \"\"),

\"substitutability\": attrs.get(\"substitutability\", \"\"),

\"concentration_risk\": attrs.get(\"concentration_risk\", \"\"),

})

output = io.StringIO()

fieldnames =

[\"provider_name\",\"provider_type\",\"country\",\"criticality\",

\"exit_plan_status\",\"supported_function\",\"contract_end_date\",

\"substitutability\",\"concentration_risk\"]

writer = csv.DictWriter(output, fieldnames=fieldnames)

writer.writeheader()

writer.writerows(rows)

output.seek(0)

filename = f\"dora_ict_register_{tenant_id}.csv\"

return StreamingResponse(

iter([output.getvalue()]),

media_type=\"text/csv\",

headers={\"Content-Disposition\": f\"attachment;

filename={filename}\"},

)

**✅ Critères de sortie P1.15**

  ----------------------------------------------------------------------------------------------------------------------------------------
  ✓ curl http://localhost:8000/api/v1/tenants/acmecorp/exports/dora/ict-register -H \"Authorization: Bearer \$TOKEN\" --output dora.csv

  ----------------------------------------------------------------------------------------------------------------------------------------

P1.16 --- NOUVEAU : Réconciliation métier↔IT, version légère

**Objectif :** faire exister le lien processus↔asset, sans construire de moteur BIA.

Fichiers à créer

-   packages/core/models/enums.py --- ajout de BUSINESS_PROCESS et BUSINESS_FUNCTION à NodeType (l\'enum existant n\'est pas remplacé, seulement complété)

-   packages/loaders/business_process_loader.py

-   packages/loaders/tests/test_business_process_loader.py

-   tests/fixtures/acmecorp_business_processes.csv

enums.py --- ajout

class NodeType(StrEnum):

# \... valeurs existantes inchangées \...

THIRD_PARTY = \"THIRD_PARTY\"

CONTRACT = \"CONTRACT\"

# NOUVEAU (P1.16)

BUSINESS_PROCESS = \"BUSINESS_PROCESS\"

BUSINESS_FUNCTION = \"BUSINESS_FUNCTION\"

class EdgeType(StrEnum):

# \... valeurs existantes inchangées (dont OWNS, ajoutée en P1.6) \...

business_process_loader.py

# packages/loaders/business_process_loader.py

\"\"\"Charge des processus métier depuis un CSV et les relie aux assets

déjà présents dans le graphe via EdgeType.SUPPORTS (existe depuis P0).

Alimentation manuelle assumée --- pas de connecteur temps réel : le BIA

reste une donnée humaine, comme chez Arnaud/Roméo.\"\"\"

import csv

import uuid

from datetime import datetime, timezone

from packages.core.models.node import CuzNode

from packages.core.models.edge import CuzEdge

from packages.core.models.enums import NodeType, EdgeType

from packages.core.scoring import compute_confidence, compute_freshness

class BusinessProcessLoader:

def __init__(self, tenant_id: str):

self.tenant_id = tenant_id

def load_csv(self, path: str) -\> tuple[list[CuzNode], list[tuple[CuzNode, str]]]:

\"\"\"Retourne (nœuds BUSINESS_PROCESS créés, liste de (nœud, asset_external_id)

à relier par le caller une fois les assets résolus dans Neo4j).\"\"\"

nodes = []

links = []

with open(path, newline=\"\", encoding=\"utf-8\") as f:

reader = csv.DictReader(f)

for row in reader:

last_seen = datetime.now(timezone.utc)

node = CuzNode(

tenant_id=self.tenant_id,

node_type=NodeType.BUSINESS_PROCESS,

name=row[\"process_name\"],

external_id=f\"bp-{row[\'process_name\']}\",

confidence_score=compute_confidence([\"manual\"]),

freshness_score=compute_freshness(NodeType.BUSINESS_PROCESS, last_seen),

sources=[\"manual\"],

last_seen=last_seen,

attributes={\"criticality_raw\": row.get(\"criticality\")},

tags={\"source\": \"manual\", \"origin\": \"business_process_csv\"},

)

nodes.append(node)

links.append((node, row[\"supporting_asset_external_id\"]))

return nodes, links

def make_supports_edge(self, process_node: CuzNode, asset_node: CuzNode) -\> CuzEdge:

last_seen = datetime.now(timezone.utc)

return CuzEdge(

tenant_id=self.tenant_id,

edge_type=EdgeType.SUPPORTS,

source_id=asset_node.id,

target_id=process_node.id,

confidence_score=compute_confidence([\"manual\"]),

freshness_score=compute_freshness(NodeType.BUSINESS_PROCESS, last_seen),

sources=[\"manual\"],

)

Fixture AcmeCorp --- acmecorp_business_processes.csv

process_name,criticality,supporting_asset_external_id

Paiement client,critical,Acme-Payment-SaaS

Onboarding fournisseur,high,payment-app

Facturation interne,medium,backend

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critère de sortie P1.16** Le loader crée au moins 3 nœuds BUSINESS_PROCESS sur AcmeCorp, chacun relié par SUPPORTS à un asset déjà présent dans le graphe (résolu par external_id). MATCH (bp:CuzNode {node_type:\'BUSINESS_PROCESS\'})\<-[:CUZ_EDGE {edge_type:\'SUPPORTS\'}]-(a) RETURN bp.name, a.name retourne au moins 3 lignes.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.17 --- NOUVEAU : DICT et criticité --- convention légère

**Objectif :** donner un début de réponse à « pourquoi cet actif compte », sans pondération dynamique par contexte réglementaire (jugée non stabilisée, cf. Plan V3 §1).

Fichiers à créer

-   packages/core/scoring/criticality.py

-   packages/core/scoring/tests/test_criticality.py

-   docs/dict-convention.md

criticality.py

# packages/core/scoring/criticality.py

\"\"\"Convention DICT légère : attributes[\'criticality\'] =

{\'D\': 1-4, \'I\': 1-4, \'C\': 1-4, \'T\': 1-4}. Aucune pondération par contexte

de conformité n\'est calculée ici --- jugement humain documenté à part.\"\"\"

from typing import Optional

from packages.core.models.node import CuzNode

def node_criticality_order(node: CuzNode) -\> Optional[int]:

\"\"\"Retourne le max des 4 axes DICT s\'ils sont renseignés, None sinon.

Ne PAS interpoler ni supposer une valeur par défaut.\"\"\"

dict_attrs = node.attributes.get(\"criticality\")

if not isinstance(dict_attrs, dict):

return None

values = [dict_attrs.get(axis) for axis in (\"D\", \"I\", \"C\", \"T\")]

values = [v for v in values if isinstance(v, int) and 1 \<= v \<= 4]

return max(values) if values else None

def max_criticality_along_path(node_criticalities: list[Optional[int]]) -\> Optional[int]:

\"\"\"Propage la criticité max le long d\'un chemin DEPENDS_ON/SUPPORTS.

Simple max --- pas de pondération, pas de décroissance avec la distance.\"\"\"

known = [c for c in node_criticalities if c is not None]

return max(known) if known else None

docs/dict-convention.md --- extrait

Documenter la convention DICT (échelle 1-4 par axe, 3-3-3-3 = priorité 1 selon la terminologie utilisée en réunion) et signaler explicitement que la pondération C/I/A par contexte réglementaire (paiement vs RGPD) n\'est pas automatisée : c\'est un choix assumé, pas un manque. La formule utilitaire ne fait qu\'un max, jamais une moyenne pondérée par un contexte non stabilisé.

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critère de sortie P1.17** node_criticality_order() retourne None sur un nœud sans attributs criticality (pas de fausse précision) et le bon max sur un nœud renseigné. max_criticality_along_path() testé sur 3 cas : tout renseigné, partiellement renseigné, rien renseigné.

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.18 --- NOUVEAU : Shadow IT mesurable

**Objectif :** transformer « on assume un taux d\'inconnu » en indicateur vérifiable de couverture CMDB --- pas une mesure de l\'inconnu total, qui est par définition impossible.

Fichiers à créer

-   packages/detection/rules/shadow_it.py

-   services/api/routers/coverage.py

-   packages/detection/tests/test_shadow_it.py

shadow_it.py --- règle SHADOW-IT-001

# packages/detection/rules/shadow_it.py

\"\"\"Tout nœud vu par au moins une source technique mais absent de la CMDB

déclarée (ServiceNow) est un candidat shadow IT. C\'est un indicateur de

couverture CMDB, pas une mesure de complétude du SI réel.\"\"\"

SHADOW_IT_CYPHER = \"\"\"

MATCH (n:CuzNode {tenant_id:\$tenant_id})

WHERE NOT \'servicenow\' IN n.sources

AND size(n.sources) \> 0

RETURN n.id AS node_id, n.name AS node_name, n.sources AS sources

\"\"\"

def rule_shadow_it(session, tenant_id: str) -\> list[Finding]:

result = session.run(SHADOW_IT_CYPHER, tenant_id=tenant_id)

findings = []

for rec in result:

findings.append(Finding(

tenant_id=tenant_id,

rule_id=\"SHADOW-IT-001\",

severity=\"MEDIUM\",

title=\"Actif absent de la CMDB déclarée\",

description=f\"{rec[\'node_name\']} est vu par {rec[\'sources\']} \"

f\"mais n\'apparaît pas dans ServiceNow.\",

affected_nodes=[rec[\"node_id\"]],

affected_node_names=[rec[\"node_name\"]],

remediation_hint=\"Vérifier si cet actif doit être déclaré en CMDB \"

\"ou s\'il s\'agit d\'un composant technique interne \"

\"(ex: dépendance logicielle) hors périmètre CMDB.\",

))

return findings

RULES = [rule_shadow_it]

coverage.py --- endpoint de couverture

# services/api/routers/coverage.py

from fastapi import APIRouter

from packages.graph.client import Neo4jClient

router = APIRouter(prefix=\"/api/v1/tenants/{tenant_id}\", tags=[\"coverage\"])

\@router.get(\"/coverage\")

async def coverage(tenant_id: str):

\"\"\"% de nœuds vus techniquement ET déclarés en CMDB, vs vus

techniquement seulement. Ce n\'est PAS un taux d\'inconnu total.\"\"\"

driver = Neo4jClient.get_driver()

with driver.session() as session:

total = session.run(

\"MATCH (n:CuzNode {tenant_id:\$t}) RETURN count(n) AS c\", t=tenant_id

).single()[\"c\"]

in_cmdb = session.run(

\"MATCH (n:CuzNode {tenant_id:\$t}) WHERE \'servicenow\' IN n.sources \"

\"RETURN count(n) AS c\", t=tenant_id

).single()[\"c\"]

return {

\"total_nodes\": total,

\"declared_in_cmdb\": in_cmdb,

\"cmdb_coverage_pct\": round(100 * in_cmdb / total, 1) if total else None,

\"note\": \"Mesure la couverture CMDB, pas la part d\'inconnu réel du SI.\",

}

Scénario AC.8 bis (à ajouter au Guide AcmeCorp)

Pour rendre SHADOW-IT-001 démontrable, désynchroniser volontairement un actif entre k3d/MinIO et la PDI ServiceNow --- par exemple créer un 4ᵉ bucket MinIO (acmecorp-shadow) sans CI ServiceNow correspondant. Après scan, ce bucket doit apparaître comme finding SHADOW-IT-001 et faire baisser cmdb_coverage_pct.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **✅ Critère de sortie P1.18** SHADOW-IT-001 détecte au moins 1 actif sur AcmeCorp après le scénario AC.8 bis. GET /api/v1/tenants/acmecorp/coverage retourne un cmdb_coverage_pct \< 100.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Checklist de sortie Phase 1

Tous les items ci-dessous doivent être verts avant de démarrer Phase 2. Chaque item est vérifiable par une commande shell ou un test pytest. Base reprise intégralement de la v1.0 ; trois items sont amendés pour refléter les changements de trajectoire du Plan V3 (marqués « V3 » ci-dessous), et de nouvelles lignes sont ajoutées en fin de tableau pour les correctifs et les sous-phases P1.16-P1.18. Rien n\'est retiré.

  -------------------------------------------------------------------------------------------------------------------------------------------------------
  **Ref**      **Commande / Critère**
  ------------ ------------------------------------------------------------------------------------------------------------------------------------------
  P1.1         pytest packages/connectors/servicenow/tests/ -v → tous verts

  P1.1         ServiceNow PDI : test_connection() retourne True

  P1.1         pull_full() retourne \>20 événements couvrant les 6 tables CMDB

  P1.1 (V3)    pytest packages/connectors/servicenow/tests/ -v → test_mapper_third_party_vendor passe (FIX-1)

  P1.2         pytest packages/connectors/minio/tests/ -v → tous verts

  P1.2         3 buckets AcmeCorp ingestés, acmecorp-public avec is_public=True

  P1.2         clients_pii.csv détecté avec contains_pii=True

  P1.3         pytest packages/connectors/entra_id/tests/ -v → tous verts

  P1.3         6 utilisateurs AcmeCorp ingestés, djana.dev et svc-pipeline avec has_mfa=False

  P1.4         pytest packages/connectors/gitea/tests/ -v → tous verts

  P1.4         4 repos ingestés, qs@6.5.2 visible avec arête DEPENDS_ON, webhooks actifs

  AC.9 ★       Tous les connecteurs : POST \.../connectors/{id}/test → HTTP 200

  P1.5         pytest packages/ingestion/tests/ -v → tous verts

  P1.5         Pipeline bout-en-bout : RawEvent → Redpanda → NormalizedEvent(s)

  P1.5         Idempotence : 100 événements dupliqués → 0 doublon

  P1.5         DLQ visible : docker exec cuz-redpanda rpk topic list \| grep dlq

  P1.5 (V3)    test_normalize_gitea_repo_produces_node_and_edges passe : 1 repo + N dépendances → 1+2N NormalizedEvent

  P1.6         pytest packages/entity-resolution/tests/ -v → tous verts

  P1.6         Taux doublons \< 10% sur identifiants forts

  P1.6 (V3)    EdgeType.OWNS ajouté à l\'enum ; OwnerLinker résout djana.dev → backend sur AcmeCorp

  P1.7         pytest packages/graph/tests/ -v → tests de connexion verts

  AC.9 ★       MATCH (n:CuzNode {tenant_id:\'acmecorp\'}) RETURN count(n) → \> 200

  P1.7 (V3)    MATCH ()-[r:CUZ_EDGE {tenant_id:\'acmecorp\'}]-() RETURN r.edge_type, count(r) → DEPENDS_ON \> 0 et OWNS ≥ 1

  P1.7 (V3)    MATCH (n:CuzNode {tenant_id:\'acmecorp\'}) WHERE n.has_mfa = false RETURN count(n) → fonctionne, ≥ 2 (propriétés natives, FIX-3)

  P1.8         pytest packages/detection/tests/ -v → tous verts

  P1.8 (V3)    ATTACK-PATH-001-PARTIAL détecté : djana.dev → backend → qs@6.5.2 (3 maillons) ; version à 5 maillons repoussée en critère de sortie P2.1

  P1.8         20 règles actives, chaque Finding porte rule_id, severity, affected_nodes, remediation_hint

  P1.8         IAM-001 : djana.dev et svc-pipeline détectés

  P1.8         STORAGE-PUBLIC-001 : acmecorp-public détecté

  P1.9         Policies OPA déployées, IAM-OPA-001 retourne finding sur djana.dev

  P1.9         Findings OPA fusionnés avec findings Cypher dans GET /findings

  AC.9 ★       GET /api/v1/tenants/acmecorp/findings → ≥5 findings dont ATTACK-PATH-001-PARTIAL

  P1.10        Tous les endpoints findings testés : list, get, acknowledge, false-positive, stats, export

  P1.10        GET /docs → OpenAPI documenté automatiquement

  P1.11        http://localhost:3000/dashboard → chargement \< 3s, données AcmeCorp réelles

  P1.11        ATTACK-PATH-001-PARTIAL visible dans le tableau findings CRITICAL

  P1.12        http://localhost:3000/graph → graphe AcmeCorp rendu \< 3s

  P1.12        Chemin d\'attaque visible en rouge, clic nœud → panel complet

  P1.13        kubectl get pods -n cuz-acmecorp → tous Running, NetworkPolicies appliquées

  P1.13        Uptime \> 99% sur 2 semaines

  P1.14        kubectl get cronjobs -n cuz-acmecorp → 5 CronJobs listés

  P1.14        freshness_score \> 0.6 sur \>80% des nœuds

  P1.15        GET /exports/dora/ict-register → CSV avec Acme-Payment-SaaS, exit_plan_status=NOT_SET

  P1.16 (V3)   ≥ 3 nœuds BUSINESS_PROCESS créés sur AcmeCorp, reliés par SUPPORTS à un asset existant

  P1.17 (V3)   node_criticality_order() et max_criticality_along_path() testés (3 cas chacun)

  P1.18 (V3)   SHADOW-IT-001 détecte ≥ 1 actif après le scénario AC.8 bis ; /coverage répond avec un pourcentage \< 100

  CI/CD        Badge CI/CD vert sur main après tous les nouveaux tests
  -------------------------------------------------------------------------------------------------------------------------------------------------------

  -----------------------------------------------------------------------------------------------------------------------
  **★** Les items AC.9 sont les critères du Guide AcmeCorp. Ils doivent être verts ici pour marquer AC.9 comme complet.

  -----------------------------------------------------------------------------------------------------------------------

Prochaines étapes --- Phase 2

Une fois tous les items de la checklist Phase 1 validés, la Phase 2 (V1 Industrielle) peut démarrer. Les premières actions seront :

1. Connecteur Kubernetes (P2.1) --- ingérer le cluster k3d AcmeCorp en mode événementiel (K8s Watch / informers). Pod legacy-job (privileged=true) détectable automatiquement.

2. Entity Resolution probabiliste Splink (P2.5) --- réduire le taux de doublons de \< 10% à \< 2%.

3. Pipeline événementiel complet (P2.7) --- passer de la réconciliation horaire à la latence \< 30s via webhooks Gitea et K8s Watch.

4. Remédiation GitOps Tier 1 (P2.10) --- générer des PRs automatiques dans Gitea pour les findings Tier 1 (bucket public, port 22 ouvert, rôle IAM inutilisé).

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Le code de chaque connecteur développé en Phase 1 sera réutilisé tel quel en Phase 2 et pour les premiers clients réels. Seuls les credentials et les endpoints changeront. C\'est la valeur architecturale fondamentale de l\'interface IConnector.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
