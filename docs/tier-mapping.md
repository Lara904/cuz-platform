# Classification des findings par tiers (P2.9)

Chaque finding porte un champ `tier`, calculé depuis son `rule_id` par `packages/detection/tier_classifier.py`.
Il est visible dans `GET /findings`, dans l'export CSV, dans les stats du dashboard (`by_tier`, findings ouverts)
et dans la colonne **Tier** du tableau des findings.

| Tier | Sens | Exécution |
|------|------|-----------|
| 0 | Tag / alerte, aucun impact | rien à exécuter |
| 1 | PR GitOps, réversible | **seul tier autonome** (P2.10) |
| 2 | Jumeau requis avant exécution | jamais seul (Phase 3) |
| 3 | Canary + validation humaine | jamais seul (Phase 4) |
| 4 | Humain uniquement | jamais automatisé |

## Règles de sûreté

- **Fail-safe (RÈGLE 7)** : une règle absente du mapping est en Tier 4. La correspondance est exacte, sensible à la
  casse. Les tests exigent qu'**aucune règle enregistrée ne dépende de ce défaut** (entrée explicite pour chacune) et
  qu'**aucune entrée ne vise une règle inexistante** : une faute de frappe ne passe pas pour un Tier 4 par défaut.
- **`can_automate(rule_id)`** ne regarde que le tier. Pour décider d'agir sur un finding précis, utiliser
  **`can_automate_finding(finding)`** : Tier 1, finding `open`, et `confidence_score >= 0.7` (RÈGLE 3).
- **Le tier n'est pas stocké** : c'est un champ calculé du modèle `Finding`. Un `tier` présent dans un message
  Kafka ou un JSON est ignoré et recalculé, donc impossible à forger.
- L'ensemble des règles Tier 1 est figé par un test : en ajouter une (donc l'autoriser à agir seule) oblige à
  modifier ce test.
- **Rien n'exécute encore d'action automatique** : P2.9 classe, P2.10 (PR GitOps) agira. Aujourd'hui, la garantie
  « aucune action sur un Tier 4 » tient parce qu'aucun code d'action n'existe, et sera tenue par `can_automate_finding`
  quand il en existera.

## Mapping des 26 règles (21 Cypher + 5 OPA)

Colonne **Origine** : *guide* = tier fixé par le guide V3 ; *décision* = tier fixé explicitement hors guide ;
*défaut sûr* = non classée par le guide, mise en Tier 4 explicite **en attente d'arbitrage** (aucune automatisation
n'a été déduite).

| Règle | Tier | Origine | Justification |
|-------|------|---------|---------------|
| `NET-001` port SSH exposé | 1 | guide | Fermer le port dans le NSG Terraform : PR réversible |
| `STORAGE-PUBLIC-001` bucket public | 1 | guide | Retirer la policy publique : PR réversible |
| `IAM-001` identité sans MFA | 1 | guide | PR forçant la policy MFA, **si l'identité est gérée en IaC** |
| `CIS-003` service sans owner | 1 | guide | PR ajoutant le tag `owner` |
| `CIS-011` rôle admin permanent | 1 | guide | PR réduisant la portée du rôle |
| `K8S-PRIV-001` pod privilégié | 2 | guide | Le changement de SecurityContext peut casser le pod : à tester sur jumeau |
| `IAC-DRIFT-001` dérive IaC | 2 | guide | Resynchroniser a un impact difficile à prévoir à l'aveugle |
| `ATTACK-PATH-001-PARTIAL` chemin d'attaque | 3 | guide | Plusieurs maillons, impact large : canary + validation humaine |
| `OAUTH-LATERAL-001` SA OAuth vers PII | 3 | guide | Restreindre un rôle de service peut couper un usage légitime |
| `DORA-THIRD-PARTY-001` prestataire sans plan de sortie | 4 | guide | Décision contractuelle, pas technique |
| `SHADOW-IT-001` actif hors CMDB | 4 | guide | Arbitrage métier : déclarer ou isoler |
| `IAM-OPA-001` humain sans MFA (OPA) | 0 | guide | Doublon d'`IAM-001` côté OPA : information seule |
| `CIS-004` nœud stale | 0 | décision | Un nœud dont la fraîcheur est tombée sous 0.2 n'appelle aucune remédiation : il faut une alerte immédiate, sans aucun impact. C'est exactement la définition du Tier 0 (« tag/alerte, aucun impact »). Aucune action n'est possible ni utile sur une donnée périmée : le tier ne donne donc aucune autorisation d'agir |
| `CIS-001`, `CIS-002`, `CIS-005`, `CIS-006`, `CIS-007`, `CIS-008`, `CIS-009`, `CIS-010`, `CIS-012` | 4 | défaut sûr | Le guide ne les classe pas |
| `NET-OPA-001`, `TLS-OPA-001`, `OWN-OPA-001`, `STORAGE-OPA-001` | 4 | défaut sûr | Le guide ne classe que `IAM-OPA-001` parmi les règles OPA |

13 règles sur 26 sont en Tier 4 faute de justification claire, pas par décision : 9 règles CIS et 4 règles OPA.
Les reclasser est un choix de produit : modifier `RULE_TIER_MAPPING` (et ce tableau). Candidates, à confirmer :
les règles OPA qui doublonnent une règle Cypher.

## Écarts avec le code du guide V3

- `IaC-DRIFT-001` → **`IAC-DRIFT-001`** : le guide avait une casse qui ne correspond à aucune règle réelle ; la règle
  serait restée en Tier 4 par défaut, sans erreur.
- `ATTACK-PATH-001` (5 maillons) n'existe pas comme règle : seule `ATTACK-PATH-001-PARTIAL` est enregistrée. Quand la
  règle complète sera ajoutée, elle sera Tier 4 par défaut jusqu'à classification explicite, et le test de couverture
  échouera pour le rappeler.
- Le guide parle de « 20 règles Cypher » : il y en a **21** (`rules/*.py`) et **5** règles OPA (`rules/opa/*.rego`).
- Le guide ne classe pas 10 règles CIS et 4 règles OPA. `CIS-004` a été classée Tier 0 par décision ; les 13 autres
  restent en Tier 4 (voir ci-dessus).
- `can_automate_finding` est ajouté pour appliquer la RÈGLE 3, absente de `can_automate(rule_id)`.

## Hors du mapping

- **Alertes cloud** (`run_cloud_alerts`) : leur `rule_id` vient de la source (Defender) ou vaut `CLOUD-ALERT`.
  Jamais mappées, donc Tier 4 : une alerte externe ne s'automatise pas.
- **Ajouter une règle** : l'ajouter à `RULE_TIER_MAPPING`. Les tests échouent tant qu'elle n'a pas d'entrée explicite.
