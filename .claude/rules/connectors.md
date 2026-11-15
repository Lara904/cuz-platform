# Règles — Connecteurs CUz

## Structure obligatoire d'un connecteur

```
packages/connectors/<nom>/
├── __init__.py
├── connector.py    # hérite IConnector
├── mapper.py       # RawEvent → CuzNode / CuzEdge
└── tests/
    ├── __init__.py
    ├── test_connector.py
    └── test_mapper.py
```

## Interface IConnector — méthodes à implémenter

```python
class MonConnector(IConnector):
    async def pull_full(self) -> list[RawEvent]: ...       # scan complet (quotidien)
    async def pull_delta(self, since: datetime) -> list[RawEvent]: ...  # delta (horaire)
    async def health_check(self) -> bool: ...
```

## RÈGLE ABSOLUE — jamais d'écriture directe Neo4j

```python
# CORRECT — publier dans Redpanda
await self.producer.send(
    topic=f"cuz.raw.{self.tenant_id}",
    value=raw_event.model_dump_json().encode()
)

# INTERDIT — ne jamais faire ça
neo4j_session.run("CREATE (n:Node ...)")
```

## CuzNode — champs obligatoires dans le mapper

```python
CuzNode(
    id=f"{connector_name}:{external_id}",  # format standardisé
    type=NodeType.XXX,
    tenant_id=tenant_id,
    label="nom lisible",
    confidence_score=0.85,   # OBLIGATOIRE, jamais omis
    freshness_score=1.0,     # OBLIGATOIRE, 1.0 au moment du scan
    sources=[connector_name],
    attributes={},
    tags={},
)
```

## NormalizedEvent — toujours node ET edge (FIX-2)

```python
NormalizedEvent(
    node=cuz_node,           # CuzNode | None
    edge=cuz_edge,           # CuzEdge | None  <- NE PAS OUBLIER
    tenant_id=tenant_id,
    source_connector="mon_connecteur",
    timestamp=datetime.utcnow(),
)
```

## FIX-1 — ServiceNow mapper (servicenow/mapper.py)

```python
# Ligne à corriger — discriminer APPLICATION vs THIRD_PARTY
node_type = NodeType.THIRD_PARTY if rec.get("u_vendor_type") == "third_party" else NodeType.APPLICATION
```

## Propriétés natives Neo4j à promouvoir (FIX-3)

Ces attributs doivent être des propriétés Neo4j top-level (pas seulement dans le blob `attributes`) :
- `has_mfa` (bool) — sur les USER
- `is_public` (bool) — sur les STORAGE
- `privileged`, `run_as_root` (bool) — sur les WORKLOAD
- `criticality` (dict) — sur tout nœud DICT-classifié
- `owner` (str) — sur tout nœud avec responsable

## Tests obligatoires pour chaque connecteur

- `test_pull_full()` — mock de la source, RawEvents bien formés
- `test_mapper_node()` — confidence_score et freshness_score présents
- `test_mapper_edge()` — si le connecteur produit des arêtes
- `test_health_check()` — mock OK et mock KO

## Variables d'environnement

Toujours via `.env` + `python-dotenv`. Jamais de secret en dur dans le code.
