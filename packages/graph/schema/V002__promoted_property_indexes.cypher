// packages/graph/schema/V002__promoted_property_indexes.cypher
// ============================================================
// FIX-3 : index sur les propriétés Neo4j natives promues.
// Les règles de détection filtrent sur ces propriétés (n.has_mfa = false, etc.),
// jamais sur le blob JSON `attributes`.
// ============================================================

CREATE INDEX cuz_node_has_mfa IF NOT EXISTS
  FOR (n:CuzNode) ON (n.has_mfa);

CREATE INDEX cuz_node_is_public IF NOT EXISTS
  FOR (n:CuzNode) ON (n.is_public);

CREATE INDEX cuz_node_privileged IF NOT EXISTS
  FOR (n:CuzNode) ON (n.privileged);
