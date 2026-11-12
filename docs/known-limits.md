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

## Pipeline événementiel (P2.7)

### Webhook Gitea : refuse tout tant qu'il n'est pas configuré (échec fermé)
`POST /api/v1/webhooks/gitea` répond 503 sans `GITEA_WEBHOOK_SECRET` : accepter des événements non signés
laisserait n'importe qui écrire dans le pipeline. Pour l'activer : définir `GITEA_WEBHOOK_SECRET` (et
`GITEA_URL`, `GITEA_ADMIN_TOKEN`) dans le secret `cuz-acmecorp-secrets`, puis relancer un scan Gitea, qui
met à jour les webhooks existants avec le secret. `CUZ_WEBHOOK_URL` doit être joignable DEPUIS Gitea
(`localhost:8000` par défaut ne l'est pas depuis le conteneur Gitea). Tenant fixé par
`CUZ_WEBHOOK_TENANT` (défaut acmecorp) ; résolution par org/dépôt prévue en P2.14.
Seul un push sur la branche par défaut rafraîchit le graphe ; create/delete/pull_request sont ignorés.
**Non vérifié en réel** : le chemin Gitea -> webhook -> graphe n'a été testé qu'avec des signatures et un
connecteur simulés, faute de secret et d'URL joignable dans l'environnement.

### Le pipeline événementiel n'est pas déployé sur le cluster
`python -m packages.ingestion.event_pipeline --tenant acmecorp` (watch Kubernetes + détection cloud)
tourne comme processus local. En faire un Deployment demande l'authentification in-cluster du connecteur
Kubernetes (il lit aujourd'hui un kubeconfig), non traitée ici.

### Ce que la latence mesurée recouvre
- `scripts/measure_ingest_latency.py` : publication du RawEvent -> nœud visible dans Neo4j, sur 100
  événements consécutifs et un tenant jetable (supprimé ensuite), précision ±50 ms. Ne couvre pas le délai
  source -> connecteur ni la latence réseau d'un vrai webhook.
- `EventPipeline.measure_p95_latency()` : délai connecteur -> bus seulement, pas le bout en bout.
- Cloud : le poll est à 30 s (`CLOUD_DETECTION_POLL_SECONDS`), donc la pire latence cloud est ≈ 30 s + le
  pipeline ; le critère (< 2 min) tient par construction, il n'a pas été mesuré sur 100 alertes réelles.

### Suppressions non propagées
Le watch Kubernetes ignore DELETED : le graphe ne supprime jamais de nœud, la fraîcheur décroît
(stale-detection P1.14). Un pod supprimé reste donc dans le graphe jusqu'à ce que sa fraîcheur le signale.
