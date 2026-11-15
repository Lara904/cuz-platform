# Règles — Scoring CUz

## Les deux scores obligatoires

Tout CuzNode et tout CuzEdge doit porter ces deux scores. Sans exception.

### confidence_score (0.0 → 1.0)
Mesure la fiabilité de la donnée — basé sur la complétude et la cohérence des champs.

```python
from packages.core.scoring import compute_confidence

confidence = compute_confidence(raw_record)
# < 0.7 → quarantaine, aucune action automatique
# >= 0.7 → éligible au graphe de production
```

### freshness_score (0.0 → 1.0)
Mesure la fraîcheur de la donnée — décroît avec le temps depuis le dernier scan.

```python
from packages.core.scoring import compute_freshness

freshness = compute_freshness(last_seen=datetime.utcnow())
# 1.0 au moment du scan
# décroît selon la fréquence attendue du connecteur
```

## Seuil de confiance — règle non négociable

```python
# Jamais d'action automatique sous 0.7
if node.confidence_score < 0.7:
    send_to_quarantine(node)
    return

write_to_neo4j(node)
```

## Criticité DICT (P1.17)

Convention pour les nœuds avec classification métier :

```python
node.attributes["criticality"] = {
    "D": 3,  # Disponibilité (1-4)
    "I": 2,  # Intégrité (1-4)
    "C": 4,  # Confidentialité (1-4)
    "T": 1,  # Traçabilité (1-4)
}
```

Valeur par défaut : `None` si non renseignée. Ne jamais inventer une valeur.

Fonction utilitaire (packages/core/scoring/criticality.py) :
```python
max_criticality_along_path(start_node_id, relationship_types=["DEPENDS_ON", "SUPPORTS"])
# Propage la criticité max le long du chemin — simple max, pas de pondération
```

## Propagation de la fraîcheur

Quand un connecteur échoue, ne pas supprimer les nœuds existants.
Mettre à jour `last_successful_sync` dans la table PostgreSQL `connector_status`.
Le dashboard affiche l'âge du dernier scan réussi.

## Règles de détection — seuils

Les règles Cypher (P1.8) filtrent sur les propriétés natives, jamais sur le blob JSON :

```cypher
-- ATTACK-PATH-001 — exemple de filtre correct
MATCH (u:Node {type: 'USER', has_mfa: false})
MATCH (s:Node {type: 'STORAGE', is_public: true})
MATCH (w:Node {type: 'WORKLOAD', privileged: true})
```
