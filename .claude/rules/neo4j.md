# Règles — Écriture Neo4j (Graph Writer)

## Principe fondamental

Le Graph Writer (`graph/writer.py`) est le SEUL composant autorisé à écrire dans Neo4j.
Il consomme les `NormalizedEvent` depuis Redpanda topic `cuz.normalized.{tenant_id}`.

## Upsert de nœuds — pattern MERGE obligatoire

```cypher
MERGE (n:Node {id: $id, tenant_id: $tenant_id})
ON CREATE SET
    n.type = $type,
    n.label = $label,
    n.confidence_score = $confidence_score,
    n.freshness_score = $freshness_score,
    n.sources = $sources,
    n.attributes = $attributes,
    n.created_at = datetime(),
    n.updated_at = datetime(),
    n.has_mfa = $has_mfa,
    n.is_public = $is_public,
    n.privileged = $privileged,
    n.criticality = $criticality,
    n.owner = $owner
ON MATCH SET
    n.confidence_score = $confidence_score,
    n.freshness_score = $freshness_score,
    n.sources = $sources,
    n.attributes = $attributes,
    n.updated_at = datetime(),
    n.has_mfa = $has_mfa,
    n.is_public = $is_public,
    n.privileged = $privileged,
    n.criticality = $criticality,
    n.owner = $owner
```

## FIX-3 — Ne JAMAIS filtrer avec CONTAINS sur JSON

```cypher
-- INTERDIT (casse si espace après ":")
WHERE n.attributes CONTAINS '"has_mfa":false'

-- CORRECT (propriété native)
WHERE n.has_mfa = false
```

## Upsert d'arêtes

```cypher
MATCH (a:Node {id: $source_id, tenant_id: $tenant_id})
MATCH (b:Node {id: $target_id, tenant_id: $tenant_id})
MERGE (a)-[r:EDGE_TYPE]->(b)
ON CREATE SET
    r.confidence_score = $confidence_score,
    r.freshness_score = $freshness_score,
    r.attributes = $attributes,
    r.created_at = datetime()
ON MATCH SET
    r.confidence_score = $confidence_score,
    r.freshness_score = $freshness_score,
    r.updated_at = datetime()
```

## Isolation par tenant

Chaque requête filtre TOUJOURS sur `tenant_id`. Ne jamais écrire une requête sans ce filtre.

## Seuil de confiance

Ne jamais écrire un nœud avec `confidence_score < 0.7` dans le graphe de production.
Les nœuds sous ce seuil vont en quarantaine (table PostgreSQL).

## Index Neo4j requis

```cypher
CREATE INDEX node_id_tenant IF NOT EXISTS FOR (n:Node) ON (n.id, n.tenant_id);
CREATE INDEX node_type IF NOT EXISTS FOR (n:Node) ON (n.type);
CREATE INDEX node_has_mfa IF NOT EXISTS FOR (n:Node) ON (n.has_mfa);
CREATE INDEX node_is_public IF NOT EXISTS FOR (n:Node) ON (n.is_public);
CREATE INDEX node_privileged IF NOT EXISTS FOR (n:Node) ON (n.privileged);
```
