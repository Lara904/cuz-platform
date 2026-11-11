# Limites connues

Limites assumées, à traiter plus tard. Ce ne sont pas des défauts de code mais des choix de périmètre
ou des contraintes de l'environnement de test.

## Entity Resolution (P2.5 / P2.6)

### Fusion réelle dans Neo4j : non implémentée
La décision « Fusionner » de l'interface de validation (`/graph/entity-resolution`) est **enregistrée**
(table PostgreSQL `er_decisions`, append-only, règle 4) mais **n'applique aucune fusion dans le graphe**.
L'API le signale : `graph_merge_applied: false`. Seul le GraphWriter écrit dans Neo4j (règle 1) et il n'a
ni type d'événement de fusion ni opération associée.

C'est un sujet d'architecture à part, à traiter plus tard, qui doit décider au minimum :
- la **fusion d'arêtes** : redirection des arêtes du nœud absorbé, déduplication, conflit de scores ;
- l'**historique des sources** : conserver la provenance de chaque nœud d'origine (sources,
  external_ids, scores) après fusion ;
- l'**annulation** : pouvoir défaire une fusion (donc ne pas supprimer le nœud absorbé sans trace).

### Taux de doublons < 2 % non démontrable à l'échelle actuelle
AcmeCorp compte 284 nœuds (le guide en suppose plus de 1000) et aucune paire de vérité terrain
(rien n'a été fusionné par P1.6). Le taux affiché (`duplicate_rate_basis: estimated_from_model`) est
estimé par le modèle, pas confirmé par un humain. Le graphe n'est pas gonflé de données fictives.

### Modèle partiellement entraîné
Seuls les u sont estimés sur les données réelles. Le prior (10 % de doublons, chiffre du guide pour P1.6)
et les m sont spécifiés : l'EM non supervisé est dégénéré sur si peu de doublons. Les m se recalibrent
avec `python -m packages.entity_resolution.probabilistic_resolver --tenant <t> --retrain-from-decisions`
dès que 20 paires au moins sont validées « merge ».

### Recall limité
Un doublon n'ayant qu'une seule preuve (IP seule, ou nom seul) n'est jamais fusionné automatiquement et
reste sous le seuil de revue (0,60) avec les priors actuels. Les noms d'une autre convention (suffixe
de domaine, schéma uniforme) ne sont pas vus.

### Critère « 100 paires traitées » (P2.6)
La file de revue d'AcmeCorp est vide (0 paire en zone grise). Des paires synthétiques ne sont pas
injectées : elles entreraient dans une table immuable et fausseraient le recalibrage.
