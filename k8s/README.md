# Manifestes Kubernetes — CUz sur k3d acmecorp (P1.13)

Namespace `cuz-acmecorp`, séparé de `production` (pods applicatifs du scénario, dont `legacy-job`).

## Contenu
- `namespace.yaml` : PodSecurity **restricted** en enforce.
- `limit-range.yaml` : valeurs par défaut et bornes des conteneurs.
- `network-policies.yaml` : deny-all, DNS, ingress Traefik → API (8000), sorties ciblées.
- `cuz-api/` : ServiceAccount (sans token), Deployment (2 réplicas, conforme restricted), Service, HPA (2–5 pods, CPU 70 %).

## Prérequis avant `kubectl apply -k k8s`
1. Image construite et importée dans le cluster :
   `docker build -t cuz-api:0.1.0 -f services/api/Dockerfile .`
   `k3d image import cuz-api:0.1.0 -c acmecorp`
2. Secret `cuz-acmecorp-secrets` créé hors dépôt, avec les variables de `.env` utilisées par l'API
   (DATABASE_URL, JWT_SECRET_KEY, NEO4J_*, KAFKA_BOOTSTRAP_SERVERS, OPA_URL…).
   Ne jamais committer les valeurs.

## Vérification sans déploiement
- `kubectl apply -k k8s --dry-run=client` : passe.
- `kubectl apply -k k8s --dry-run=server` : le namespace n'existant pas encore, le dry-run
  serveur échoue sur les objets namespacés. Le namespace seul passe. Les objets ont été validés
  serveur sur une copie ciblant `default` (schémas, NetworkPolicies, LimitRange, HPA).
  L'admission PSS ne sera testée qu'au déploiement réel.

## Limites connues
- Les services de données (Neo4j, PostgreSQL, Redpanda, Redis, OPA) tournent via compose, hors cluster.
  Les pods doivent les joindre par leur hôte ; à définir dans le Secret.
- Les NetworkPolicies de sortie limitent les ports, pas les destinations.
- Les workers (`detection`, `ingestion`, `reconciliation`) n'ont ni code ni Dockerfile : non inclus.
