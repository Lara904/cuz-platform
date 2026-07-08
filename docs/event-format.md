# Format des événements canoniques — CUz

## Vue d'ensemble

Tout connecteur CUz produit des **RawEvents**. Le pipeline de normalisation les transforme en **NormalizedEvents** avant injection dans le graphe Neo4j. Ce format est le contrat entre les connecteurs et le pipeline d'ingestion.

```
Connecteur → RawEvent → [Normalizer] → NormalizedEvent → Neo4j
```

Aucun composant ne peut écrire directement dans Neo4j sans passer par ce pipeline.

---

## RawEvent

Produit par les connecteurs. Contient les données brutes de la source, sans transformation.

```python
class RawEvent(BaseModel):
    event_id: str           # UUID unique de l'événement
    tenant_id: str          # Isolation multi-tenant
    source: str             # Ex: 'servicenow', 'azure', 'entra_id', 'github'
    event_type: EventType   # Type de mutation (voir ci-dessous)
    timestamp: datetime     # Horodatage UTC de l'événement
    raw_data: Dict[str, Any]  # Données brutes de la source, format libre
    schema_version: str     # Version du schéma (défaut: '1.0')
```

### Exemple — Serveur détecté par Azure

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "stellantis-financial",
  "source": "azure",
  "event_type": "NODE_CREATED",
  "timestamp": "2026-06-01T10:30:00Z",
  "raw_data": {
    "id": "/subscriptions/abc/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod-01",
    "name": "vm-prod-01",
    "location": "westeurope",
    "properties": {
      "hardwareProfile": {"vmSize": "Standard_D4s_v3"},
      "osProfile": {"computerName": "vm-prod-01"}
    }
  },
  "schema_version": "1.0"
}
```

---

## NormalizedEvent

Produit par le Normalizer après transformation du RawEvent. Contient un `CuzNode` ou `CuzEdge` prêt pour Neo4j.

```python
class NormalizedEvent(BaseModel):
    event_id: str           # Nouvel UUID pour cet événement normalisé
    raw_event_id: str       # Traçabilité vers le RawEvent source
    tenant_id: str
    source: str
    event_type: EventType
    timestamp: datetime
    node: Optional[CuzNode] = None  # Présent pour NODE_CREATED/UPDATED/DELETED
    edge: Optional[CuzEdge] = None  # Présent pour EDGE_CREATED/UPDATED/DELETED
    schema_version: str
```

### Règle : node XOR edge

Un NormalizedEvent contient soit un `node`, soit un `edge`, jamais les deux, jamais aucun.

---

## EventType

```python
class EventType(str, Enum):
    NODE_CREATED = 'NODE_CREATED'
    NODE_UPDATED = 'NODE_UPDATED'
    NODE_DELETED = 'NODE_DELETED'
    EDGE_CREATED = 'EDGE_CREATED'
    EDGE_UPDATED = 'EDGE_UPDATED'
    EDGE_DELETED = 'EDGE_DELETED'
```

---

## Topics Redpanda

| Topic | Partitions | Contenu |
|---|---|---|
| `cuz.raw.{tenant_id}` | 6 | RawEvents produits par les connecteurs |
| `cuz.normalized.{tenant_id}` | 6 | NormalizedEvents après normalisation |
| `cuz.graph.mutations.{tenant_id}` | 3 | Mutations confirmées du graphe Neo4j |
| `cuz.graph.mutations.{tenant_id}.dlq` | 1 | Dead Letter Queue — échecs après 3 retries |

### Topics créés pour Stellantis Financial

```
cuz.raw.stellantis-financial                  (6 partitions)
cuz.normalized.stellantis-financial           (6 partitions)
cuz.graph.mutations.stellantis-financial      (3 partitions)
cuz.graph.mutations.stellantis-financial.dlq  (1 partition)
```

---

## Garanties du pipeline

- **Idempotence** — Le même RawEvent traité deux fois ne crée pas de doublon dans Neo4j (MERGE Cypher).
- **Traçabilité** — Chaque NormalizedEvent référence son RawEvent source via `raw_event_id`.
- **Dead Letter Queue** — Tout événement en échec après 3 retries est routé vers la DLQ pour analyse.
- **Isolation tenant** — Chaque tenant a ses propres topics. Aucun événement cross-tenant n'est possible.