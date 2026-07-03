// packages/graph/schema/V001__initial_schema.cypher
// ============================================================
// Contraintes d'unicité — identifiant interne par tenant
// ============================================================

// Unicité : (tenant_id, id) par label de nœud
CREATE CONSTRAINT cuz_node_unique IF NOT EXISTS
  FOR (n:CuzNode) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

// Unicité externe : (tenant_id, external_id) pour la source lookup
CREATE CONSTRAINT cuz_node_external_unique IF NOT EXISTS
  FOR (n:CuzNode) REQUIRE (n.tenant_id, n.external_id) IS UNIQUE;

// ============================================================
// Index de performance
// ============================================================

// Index composite tenant + type (requêtes de filtrage par type)
CREATE INDEX cuz_node_tenant_type IF NOT EXISTS
  FOR (n:CuzNode) ON (n.tenant_id, n.node_type);

// Index sur last_seen (détection des nœuds stale)
CREATE INDEX cuz_node_last_seen IF NOT EXISTS
  FOR (n:CuzNode) ON (n.tenant_id, n.last_seen);

// Index sur freshness_score (filtres dashboard)
CREATE INDEX cuz_node_freshness IF NOT EXISTS
  FOR (n:CuzNode) ON (n.tenant_id, n.freshness_score);

// Index sur confidence_score (blocage actions auto < 0.7)
CREATE INDEX cuz_node_confidence IF NOT EXISTS
  FOR (n:CuzNode) ON (n.tenant_id, n.confidence_score);

// Index sur les arêtes : tenant + type
CREATE INDEX cuz_edge_tenant_type IF NOT EXISTS
  FOR ()-[r:CUZ_EDGE]-() ON (r.tenant_id, r.edge_type);