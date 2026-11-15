**PLAN DE DÉVELOPPEMENT**

*CUz --- Unified SI Intelligence Platform*

Plan V3 --- Bifurcation depuis le Plan V2, à partir du code réel du dépôt

Septembre 2026

0. Nature de ce document

Ce plan ne remplace pas le Plan V2 --- il en est la suite directe. Rien n\'est jeté, rien n\'est refait. Les phases et sous-phases déjà réalisées (P0 entière, P1.1 à P1.4) gardent leur numérotation et leur contenu tels quels. Les modifications de trajectoire (issues de la discussion avec Arnaud Decosterd, filtrées de façon critique --- voir §1) s\'insèrent aux points d\'entrée les moins coûteux du code existant : la plupart passent par le champ attributes déjà libre sur CuzNode/CuzEdge, sans migration de schéma.

État réel constaté (dépôt Lara904/cuz-platform, commit 359cddf, 26/09/2026)

Vérifié directement sur le code source, pas seulement sur les guides existants :

  ----------------------------------------------------------------------------------------------------------------------
  **Sous-phase**    **Statut réel constaté dans le code**
  ----------------- ----------------------------------------------------------------------------------------------------
  P0.1 à P0.8       ✅ Fait --- packages/core/, schéma Neo4j V001, API tenant, CI

  P1.1 ServiceNow   ✅ Codé --- connecteur + mapper + tests (1 bug à corriger, §3)

  P1.2 MinIO        ✅ Codé --- connecteur + mapper + tests

  P1.3 Entra ID     ✅ Codé --- connecteur + mapper + tests

  P1.4 Gitea        ✅ Codé --- connecteur + mapper + tests (arête DEPENDS_ON prête mais pas branchée)

  P1.5 à P1.15      ❌ Pas commencé --- aucun fichier dans ingestion/, entity-resolution/, graph/writer.py, detection/
  ----------------------------------------------------------------------------------------------------------------------

Tu es donc au tout début du chaînon d\'assemblage de P1 (pipeline, entity resolution, graph writer, moteur de règles), pas à mi-Phase 1 au sens large. C\'est une bonne nouvelle : les bifurcations proposées ci-dessous s\'insèrent avant que du code qu\'il faudrait défaire ait été écrit.

1. Rappel du tri des idées (réunion Arnaud / Lara / Roméo)

Tri conservé tel qu\'établi précédemment, avec les mêmes verdicts. Colonne « Entrée code » ajoutée pour situer chaque idée dans l\'arborescence réelle du dépôt.

  ---------------------------------------------------------------------------------------------------------------------------------
  **Idée**                                 **Verdict**          **Entrée code**
  ---------------------------------------- -------------------- -------------------------------------------------------------------
  Inventaire crypto / PQC                  Prendre              Nouveau connecteur packages/connectors/crypto_scan/ (P2)

  Shadow IT mesurable                      Prendre              Règle de détection + rapport de couverture (fin P1 / P2)

  SBOM (CRA)                               Prendre              Extension packages/connectors/gitea/ (P2)

  Réconciliation métier↔IT (BIA)           Version légère       Nouveaux NodeType BUSINESS_PROCESS/FUNCTION + loader CSV (fin P1)

  DICT + pondération C/I/A                 Version légère       Convention attributes[\"criticality\"] + propagation (fin P1)

  Temps (historique)                       Version légère       last_successful_sync par connecteur + snapshot daté (fin P1 / P2)

  Owner / SPOC par actif                   Version légère       attributes[\"owner\"]

  Mode dégradé (snapshot)                  Déjà quasi couvert   freshness_score existant + last_successful_sync

  Chaîne de tiers N+2                      Mémoire seulement    Aucun code --- section mémoire

  RH, contrats, business « fourre-tout »   Écarter du code      NodeType.CONTRACT déjà présent, laissé sans connecteur

  Géographie                               Tag ou rien          tags[\"geo\"], aucun traitement dédié

  Estimation de coût (TJM)                 Écarter              Aucun code

  CTEM / menace                            P3 ou plus           Hors plan V3
  ---------------------------------------------------------------------------------------------------------------------------------

2. Principe de bifurcation

Trois règles guident chaque insertion :

-   Aucune migration de schéma Pydantic bloquante. CuzNode.attributes: dict[str, Any] et CuzNode.tags: dict[str, str] sont déjà libres. DICT, criticité, owner, périmètre réglementaire y entrent par convention documentée. Le seul ajout de schéma dur est un champ optionnel valid_from / valid_to sur CuzEdge pour la temporalité (P2), nullable donc rétrocompatible.

-   Aucun connecteur existant n\'est réécrit, seulement corrigé ou étendu. Le bug ServiceNow (§3) est un correctif d\'une ligne. L\'extension Gitea (SBOM) ajoute une méthode, ne change pas les signatures existantes.

-   Les nouveaux NodeType/EdgeType s\'ajoutent à l\'enum existant, ils ne le remplacent pas. CONTRACT, GOVERNED_BY, COVERS sont déjà présents dans enums.py et seront enfin utilisés (Legal/gouvernance), pas recréés.

3. Correctifs immédiats --- avant de continuer P1.5

Ces trois points ont été repérés en relisant le code réel. Ils bloquent le critère de succès de Phase 1 (ATTACK-PATH-001) et le critère DORA. À traiter en une session, avant d\'écrire le pipeline.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Réf**   **Problème constaté**                                                                                                                                                       **Fichier**                  **Correctif**
  --------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------- -----------------------------------------------------------------------------------------------------------------------------
  FIX-1     cmdb_ci_service mappe vers APPLICATION, jamais THIRD_PARTY. La règle DORA-THIRD-PARTY-001 ne peut jamais matcher.                                                           servicenow/mapper.py L8-14   Si rec.get(\"u_vendor_type\") == \"third_party\" → NodeType.THIRD_PARTY, sinon APPLICATION.

  FIX-2     Aucune arête n\'est jamais écrite dans le graphe : map_repo_dependency_edge() produit une CuzEdge que rien ne publie tant que NormalizedEvent ne porte pas de champ edge.   À construire P1.5/P1.7       NormalizedEvent doit porter node: CuzNode\|None ET edge: CuzEdge\|None dès sa première version.

  FIX-3     Si les attributs sont stockés en JSON sérialisé et filtrés par CONTAINS \'\"has_mfa\":false\', l\'espace après \':\' dans le JSON standard casse le filtre.                 À anticiper P1.7/P1.8        Promouvoir has_mfa, is_public, privileged, criticality en propriétés Neo4j natives sur le nœud, en plus du blob attributes.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

4. Phase 1 --- Suite (numérotation V2 inchangée jusqu\'à P1.4)

P1.1 à P1.4 : acquis, ne pas retoucher, sauf FIX-1 (une ligne dans le mapper ServiceNow).

P1.5 --- Pipeline d\'ingestion + Normalizer

Inchangé de V2, avec le correctif FIX-2 intégré dès l\'écriture. NormalizedEvent porte node et edge dès la V1 du fichier. Le Normalizer appelle map_repo_dependency_edge() pour Gitea, et prévoit le même schéma pour ServiceNow (cmdb_rel_ci → arêtes) plus tard.

P1.6 --- Entity Resolution déterministe

Inchangé de V2.

P1.7 --- Graph Writer

Inchangé de V2, avec FIX-3 intégré. Les clés has_mfa, is_public, privileged, run_as_root, criticality, owner sont promues en propriétés Neo4j top-level lors de l\'upsert (en plus d\'exister dans le blob attributes), pour que les règles Cypher puissent les filtrer nativement.

P1.8 --- Moteur de règles Cypher

Inchangé de V2. Toutes les requêtes Cypher basculent sur les propriétés natives (n.has_mfa, pas n.attributes CONTAINS).

P1.9 à P1.13

Inchangées de V2.

P1.14 --- Jobs de réconciliation périodique (étendu)

Ajout d\'un champ last_successful_sync par connecteur (stocké côté PostgreSQL, table connector_status, pas dans Neo4j). C\'est le point d\'entrée du mode dégradé : si un job échoue, le dashboard affiche l\'âge du dernier scan réussi au lieu de rien. Couvre l\'essentiel du besoin « snapshot daté » sans construire un système de snapshot séparé.

P1.15 --- Export DORA

Inchangé, débloqué par FIX-1.

P1.16 --- NOUVEAU : Réconciliation métier↔IT, version légère

**Objectif :** faire exister le lien processus↔asset qu\'Arnaud identifie comme le vrai problème (« l\'IT parle assets, le métier parle processus »), sans construire de moteur BIA.

-   Ajout de deux NodeType : BUSINESS_PROCESS, BUSINESS_FUNCTION (entrevus dans le guide V2 via SUPPORTS, jamais implémentés).

-   Loader simple : CSV (ou table ServiceNow cmdb_ci_service filtrée par u_vendor_type != third_party) avec colonnes process_name, criticality, supporting_asset_external_id. Pas de connecteur temps réel --- alimentation manuelle assumée, comme le BIA d\'Arnaud.

-   Le loader crée les nœuds BUSINESS_PROCESS et les relie aux assets déjà en graphe via EdgeType.SUPPORTS (existe depuis P0).

-   Sur AcmeCorp : 5 à 10 processus fictifs suffisent (ex. « Paiement client », « Onboarding fournisseur »), reliés à Acme-Payment-SaaS et 2-3 autres nœuds déjà présents.

*Pourquoi en P1 et pas en P2 : c\'est un ajout de nœuds et d\'une arête existante, zéro dépendance sur le pipeline événementiel ou l\'entity resolution probabiliste de P2. Le faire tôt donne un deuxième cas d\'usage démonstrable avant la fin de Phase 1.*

P1.17 --- NOUVEAU : DICT et criticité --- convention légère

**Objectif :** donner un début de réponse à « pourquoi cet actif compte » sans construire de moteur de pondération complexe (le verdict reste : pas de pondération dynamique par contexte réglementaire, trop tôt et trop incertain).

-   Convention documentée dans docs/ : chaque CuzNode peut porter attributes[\"criticality\"] = {\"D\":1-4,\"I\":1-4,\"C\":1-4,\"T\":1-4} (échelle DICT façon Arnaud, 3-3-3-3 = priorité 1). Valeur par défaut None si non renseignée --- pas de fausse précision.

-   Fonction utilitaire packages/core/scoring/criticality.py::max_criticality_along_path() : propage la criticité max le long de DEPENDS_ON/SUPPORTS. Simple max, pas de pondération par conformité (jugée trop instable pour être codée maintenant).

-   Ces valeurs, une fois peuplées sur AcmeCorp, deviennent directement des features numériques utilisables en P3.2 (GNN) sans travail supplémentaire.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **⚠ ATTENTION** Ne pas construire le score de pondération C/I/A par contexte de conformité (paiement vs RGPD) en code. Arnaud lui-même le présente comme non stabilisé. Le documenter comme limite assumée dans le mémoire, pas comme feature manquante.

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

P1.18 --- NOUVEAU : Shadow IT mesurable

**Objectif :** transformer « on assume un taux d\'inconnu » en un indicateur vérifiable, sans prétendre mesurer l\'inconnu véritable (impossible par définition).

-   Règle de détection SHADOW-IT-001 : tout CuzNode dont sources ne contient pas servicenow après entity resolution. Presque gratuit : l\'entity resolution de P1.6 alimente déjà sources par nœud.

-   Endpoint /api/v1/tenants/{id}/coverage : % de nœuds vus par au moins une source technique ET présents dans la CMDB, vs % vus techniquement mais absents de la CMDB. C\'est un indicateur de couverture CMDB, pas de « part d\'inconnu total » --- distinction explicite dans la doc et le mémoire.

-   Sur AcmeCorp : désynchroniser volontairement un actif entre k3d/MinIO et la PDI ServiceNow (ex. un bucket MinIO sans CI ServiceNow correspondant). À prévoir comme scénario AC.8 bis.

5. Phase 2 --- V1 Industrielle (reprend V2, avec ajouts)

P2.1 à P2.15 : inchangées de V2 (connecteur K8s, Terraform, CVE, Splink, remédiation GitOps, agents zero-trust, audit trail, module DORA, multi-tenant, SDK).

P2.16 --- NOUVEAU : Inventaire cryptographique (CBOM)

**Objectif :** répondre au besoin le plus concret et le plus urgent identifié dans la réunion (« l\'inventaire n\'est pas fait, le risque n\'est pas géré »).

**Périmètre honnête (à ne pas dépasser dans le mémoire non plus) :**

-   Scannable : versions TLS et suites de chiffrement exposées par les endpoints (sslyze ou équivalent), algorithmes et tailles de clés des certificats X.509, bibliothèques crypto déclarées dans les dépendances (déjà lues par le connecteur Gitea).

-   Non scannable : le chiffrement au repos réellement appliqué par une base de données ou un provider cloud (déclaratif seulement, limite à consigner).

**Implémentation :**

-   Nouveau connecteur packages/connectors/crypto_scan/, réutilise IConnector sans modification. pull_full() scanne les endpoints déjà connus du graphe plutôt que de redécouvrir une infra.

-   Nouveau NodeType.CRYPTO_ASSET (algorithme + version + contexte d\'usage), relié par EdgeType.SECURES (déjà dans l\'enum) aux nœuds protégés.

-   Export aligné CycloneDX 1.6 CBOM, cohérent avec le SBOM (P2.17) --- même famille de standard, angle CRA réutilisable dans le mémoire.

-   Priorisation par inégalité de Mosca (rétention + migration \> délai avant menace quantique) sur les nœuds STORAGE portant attributes[\"retention_years\"]. Calcul simple et défendable, pas une prédiction --- directement lié au cas des données bancaires conservées 10 ans cité dans le .vtt.

-   Sur AcmeCorp : un bucket MinIO porte retention_years: 10, un endpoint HTTP délibérément laissé en TLS 1.2 avec cipher CBC faible.

P2.17 --- NOUVEAU : SBOM (extension du connecteur Gitea existant)

**Objectif :** répondre au CRA, sans nouveau connecteur.

-   Extension de gitea/connector.py : lecture de package-lock.json (ou équivalent figé) en plus de package.json, pour capter les dépendances transitives. Pertinent sur AcmeCorp : qs (CVE-2022-24999) est typiquement transitive via express, le connecteur actuel risque de ne jamais la voir si absente de package.json.

-   Séparation conceptuelle dans le mapper : NodeType.ARTIFACT (déjà dans l\'enum, inutilisé) pour le composant logiciel en général ; VULNERABILITY réservé aux composants avec CVE connue. Aujourd\'hui map_dependency() mappe tout en VULNERABILITY même sans CVE, ce qui fausse les métriques de sévérité.

-   Export CycloneDX SBOM par repo, livrable CRA direct.

P2.18 --- NOUVEAU : Snapshot daté / mode dégradé

**Objectif :** couvrir le point d\'Arnaud (« aujourd\'hui on fait des snapshots, prévoir un mode dégradé »), au-delà du last_successful_sync déjà ajouté en P1.14.

-   Job Celery export_snapshot : sérialise l\'état complet du graphe d\'un tenant (nœuds + arêtes + scores) en un fichier daté (JSON ou Parquet), déclenché manuellement ou en tâche de fond hebdomadaire.

-   Si un connecteur reste en échec au-delà d\'un seuil, le dashboard bascule l\'affichage de cette source sur « dernier snapshot connu » avec la date, plutôt que de faire disparaître silencieusement la donnée.

*C\'est un filet de sécurité, pas une fonctionnalité vendue comme continue --- la distinction doit rester visible dans l\'interface.*

6. Phase 3 --- V2 Intelligence (reprend V2, un ajout)

P3.1 à P3.14 : inchangées de V2.

P3.2 bis --- Intégration des attributs DICT/criticité comme features GNN

Prolongement naturel de P1.17 : les valeurs criticality peuplées dès P1 deviennent, sans travail de collecte supplémentaire, des features numériques structurées à côté des embeddings textuels déjà prévus en P3.2. Aucun nouveau code de collecte, seulement leur inclusion dans le pipeline d\'export HeteroData déjà prévu --- item de checklist P3.2, pas sous-phase séparée.

Le score de priorité façon « cœur de cœur » (intersection métier/cyber/conformité/risque, diagramme de Venn évoqué en réunion) devient à ce stade un sous-produit naturel du GNN : un score continu appris plutôt qu\'une formule de pondération manuelle non stabilisée. C\'est la bonne place pour cette idée --- pas avant.

7. Ce qui reste volontairement hors code (mémoire uniquement)

Repris tel quel du tri initial, sans changement :

-   Chaîne de tiers N+2 : donnée déclarative (questionnaires fournisseurs), pas une donnée de scan. Angle mort assumé du produit, pas feature manquante.

-   RH, Legal/contrats, Business « fourre-tout » : pas de connecteur. NodeType.CONTRACT reste dans l\'enum pour ne pas fermer la porte, aucun connecteur prévu au plan V3. Risque RGPD et absence de source scannable homogène.

-   Géographie : tags[\"geo\"] disponible si besoin ponctuel, pas de sous-ensemble dédié.

-   Estimation de coût (TJM interne/prestataire) : politique budgétaire interne, non généralisable en produit.

-   Gouvernance RACI complète, sponsor, comité sécurité : réalité organisationnelle indispensable côté client, mais hors produit logiciel. attributes[\"owner\"] (P1.17) est le seul artefact code ; le reste appartient au mémoire (angle « gouvernance avant outil »).

-   CTEM / exposition par la menace : évoqué en fin de réunion comme évolution du CTI, cohérent avec une Phase 4+ (au-delà de P3), non détaillé ici.

8. Points de vigilance factuels pour le mémoire

À vérifier avant citation, les affirmations suivantes issues du .vtt sont approximatives ou non sourcées en l\'état :

-   « AES-128 pas résistant » depuis 2017 : discutable --- Grover réduit la marge de sécurité, mais le NIST accepte encore AES-128 ; la recommandation CNSA 2.0 pousse vers AES-256 par prudence, pas parce qu\'AES-128 serait cassé.

-   « RSA à 8000 bits inutile si CBC dans la chaîne » : mélange deux problèmes distincts (Shor casse RSA indépendamment de sa taille de clé ; les vulnérabilités CBC sont un problème séparé). Les deux affaiblissent la sécurité, mais pas par le même mécanisme.

-   Échéances « 2035 → 2030 → 2029 » et vulnérabilité trouvée par « Anthropic avec Mythos » sur un candidat NIST PQC : aucune source vérifiable à ce stade. Ne pas citer sans référence externe confirmée.

-   La numérotation des attributions Arnaud/Lara dans le premier document (résumé) contient des erreurs déjà corrigées en conversation (« ni chaotique ni déterministe » et le rapprochement obsolescence/shadow IT sont de Lara, pas d\'Arnaud). Vérifier l\'attribution avant citation.

9. Vue d\'ensemble --- ce qui change concrètement par rapport à V2

  ------------------------------------------------------------------------------------------------------
           **V2**                **V3**
  -------- --------------------- -----------------------------------------------------------------------
  P0       8 sous-phases         Inchangé

  P1       15 sous-phases        15 sous-phases + 3 correctifs (§3) + P1.16, P1.17, P1.18

  P2       15 sous-phases        15 sous-phases + P2.16 (crypto), P2.17 (SBOM), P2.18 (snapshot)

  P3       14 sous-phases        Inchangé, + note d\'intégration P3.2 bis (pas de nouvelle sous-phase)

  P4       10 sous-phases        Inchangé
  ------------------------------------------------------------------------------------------------------

Aucune sous-phase existante n\'est supprimée ou renumérotée. Les ajouts sont additifs, positionnés en fin de phase pour ne pas perturber les dépendances déjà écrites dans le code.
