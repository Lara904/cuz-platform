# Convention DICT — criticité (P1.17)

## Échelle
Chaque actif peut porter `attributes["criticality"] = {"D": 1-4, "I": 1-4, "C": 1-4, "T": 1-4}` :
- **D** Disponibilité, **I** Intégrité, **C** Confidentialité, **T** Traçabilité.
- 1 = faible, 4 = très forte.
- Les axes non renseignés restent absents. **Aucune valeur par défaut n'est inventée.**

## Calculs disponibles
- `node_criticality_order(node)` : max des axes renseignés, ou `None`.
- `max_criticality_along_path(values)` : max propagé le long d'un chemin DEPENDS_ON / SUPPORTS.
  Simple max : pas de pondération, pas de décroissance avec la distance.

## Propriétés natives
Le writer promeut les axes en propriétés Neo4j `criticality_D`, `criticality_I`, `criticality_C`, `criticality_T`
(une map ne peut pas être une propriété Neo4j).

## Ce qui n'est PAS automatisé
La pondération C/I/A selon le contexte réglementaire (paiement ou RGPD, par exemple) n'est pas calculée.
C'est un **choix assumé** : le plan V3 (§1) juge cette pondération non stabilisée. Elle reste un jugement humain.

## Source actuelle
Aucun connecteur ne renseigne `criticality` aujourd'hui. Le processus métier importé en P1.16 garde
sa criticité brute dans `criticality_raw` (`critical`, `high`, `medium`) sans la traduire en DICT :
la traduction serait une invention.
