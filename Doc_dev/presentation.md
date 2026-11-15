**CUz : Vers un système autonome d\'urbanisation et de transformation du SI piloté par IA**

**Vision**

Les systèmes d\'information modernes sont devenus extrêmement complexes. Une grande entreprise peut posséder plusieurs milliers d\'applications, bases de données, flux, infrastructures cloud, composants réseau, pipelines CI/CD, référentiels Git et outils métiers.

Aujourd\'hui, aucun outil n\'est capable de représenter objectivement l\'ensemble de ce système sous une forme unifiée exploitable par une intelligence artificielle.

Le projet **CUz** vise à construire la première représentation unifiée et dynamique d\'un système d\'information complet, puis à développer une intelligence capable de comprendre, évaluer, simuler et progressivement transformer ce système vers des architectures plus performantes.

L\'objectif final n\'est pas seulement de cartographier le SI mais de créer un **système autonome d\'urbanisation du SI**, capable de proposer, tester, valider et exécuter des transformations complexes de manière sécurisée.

**Concept fondamental**

Nous considérons le système d\'information comme un graphe dynamique.

Chaque élément du SI devient un nœud :

-   applications

-   API

-   bases de données

-   serveurs

-   clusters Kubernetes

-   comptes cloud

-   réseaux

-   flux

-   équipes

-   processus métiers

-   pipelines CI/CD

-   composants de sécurité

-   référentiels Git

Les relations deviennent des arêtes :

-   héberge

-   consomme

-   dépend de

-   appelle

-   produit

-   transfère

-   déploie

-   surveille

-   sécurise

Nous obtenons alors :

CUz = Cartographie Unifiée du SI

Cette représentation devient l\'état complet du système d\'information.

**Architecture globale**

Sources SI

↓

Collecteurs

↓

Normalisation

↓

Graphe Unifié CUz

↓

Encodeur de Graphe

↓

Espace latent ECUz

↓

World Model JEPA

↓

Simulation de transformations

↓

Validation

↓

Jumeau numérique

↓

SI Réel

**Étape 1 : Construction de CUz**

**Sources de données**

Le système collecte les informations depuis :

**Infrastructure**

-   AWS

-   Azure

-   GCP

-   VMware

-   OpenStack

**Orchestration**

-   Kubernetes

-   OpenShift

-   Nomad

**Réseau**

-   Cisco

-   Juniper

-   SD-WAN

-   DNS

**Développement**

-   GitHub

-   GitLab

-   Bitbucket

**Observabilité**

-   Prometheus

-   Grafana

-   Datadog

-   Splunk

**CMDB**

-   ServiceNow

-   GLPI

-   EasyVista

**Architecture**

-   LeanIX

-   Ardoq

**Sécurité**

-   IAM

-   Active Directory

-   Entra ID

-   Vault

**Outils envisageables**

Le projet pourrait s\'appuyer sur :

-   Neo4j

-   JanusGraph

-   TigerGraph

-   ArangoDB

pour stocker le graphe global.

**Étape 2 : Encodage du SI**

L\'objectif est de transformer le graphe complet en représentation mathématique.

On construit :

Encoder(CUz) → ECUz

où :

CUz

est le graphe complet

et

ECUz

son embedding latent.

**Modèles possibles**

**Heterogeneous Graph Transformer**

Particulièrement adapté aux graphes contenant plusieurs types de nœuds.

**Graph Attention Network**

Pour identifier les dépendances critiques.

**GraphSAGE**

Pour l\'apprentissage incrémental.

**Graph Neural Networks hiérarchiques**

Pour gérer les SI massifs.

**Résultat**

On obtient :

ECUz ∈ R\^n

où n représente plusieurs milliers de dimensions.

Cet espace latent devient la représentation mathématique du SI.

**Étape 3 : Construction de la fonction de valeur**

Le projet ne cherche pas un SI parfait absolu.

Il cherche un SI optimal selon des objectifs.

Nous définissons :

V(CU)

la valeur d\'une architecture.

**Fonction de score**

Par exemple :

$$V(CU) = w1.Security + w2.Resilience + w3.Performance + w4.Cost + w5.Maintainability + w6.Compliance$$

avec :

$$\Sigma wi = 1$$

**Sources du score**

**Audits humains**

Architectes

**Outils d\'analyse**

SonarQube

**Outils sécurité**

SAST
DAST
IAM

**Mesures réelles**

MTTR

Lead Time

Taux d\'incident

Disponibilité

**Étape 4 : Construction de ECUgv**

Nous définissons :

ECUgv

comme l\'état latent maximisant la fonction de valeur.

Mathématiquement :

$$ECUgv = argmax(V(ECU))$$

Il ne s\'agit plus d\'un graphe cible défini manuellement mais d\'une région optimale de l\'espace latent.

**Étape 5 : Construction du World Model**

Le cœur du projet repose sur un modèle de type JEPA.

**Entrées**

ECUz

Transformation

**Sortie**

ECUfuture

**Fonction**

$$JEPA(ECUz,ET) = ECUfuture$$

où :

ET

représente une transformation.

**Espace latent des transformations**

Innovation majeure du projet.

Nous ne représentons pas uniquement les SI.

Nous représentons aussi les transformations.

Exemples :

Oracle → PostgreSQL

devient :

ET1

Monolithe → Microservices

devient :

ET2

VM → Kubernetes

devient :

ET3

Nous obtenons :

Transformation

↓

Encodeur

↓

ET

**Étape 6 : Planification**

Nous cherchons le vecteur :

$$\Delta E = ECUgv - ECUz$$

Un planificateur cherche :

$$ET*$$

tel que :

$$JEPA(ECUz,ET*) \approx ECUgv$$

Méthodes possibles :

**Reinforcement Learning**

**Monte-Carlo Tree Search**

**Diffusion Planning**

**Latent Planning**

**Goal Conditioned Planning**

**Étape 7 : Traduction en plan exécutable**

Le LLM n\'est pas le décideur principal.

Le LLM joue le rôle de traducteur.

Entrée :

ET*

Sortie :

Migration Oracle PostgreSQL

Étape 1 :

Créer cluster PostgreSQL

Étape 2 :

Migrer schéma

Étape 3 :

Migrer données

Étape 4 :

Basculer flux

Étape 5 :

Retirer Oracle

**Étape 8 : Jumeau numérique**

Toutes les transformations sont appliquées sur une copie du SI.

Architecture :

SI Réel

↓

Cartographie

↓

CUz

↓

Jumeau

Le jumeau devient un environnement de test.

**Validation niveau 1**

Validation prédictive.

$$Distance(ECUzap,ECUgv) < Distance(ECUz,ECUgv)$$

**Validation niveau 2**

Validation du jumeau.

Après exécution :

ECUzaj

doit être proche de :

ECUzap

Formellement :

$$\mid \mid ECUzaj - ECUzap \mid \mid < \varepsilon$$

**Validation niveau 3**

Validation humaine.

Architectes

RSSI

Responsables applicatifs

Métiers

**Étape 9 : Déploiement réel**

Après validation :

Agent PostgreSQL

Agent Kubernetes

Agent Réseau

Agent Sécurité

agissent sur le SI réel.

**Architecture multi-agents**

Principe Zero Trust.

Aucun agent n\'a accès à l\'ensemble du SI.

Chaque agent possède :

-   un périmètre limité

-   des droits minimaux

-   un objectif unique

**Boucle d\'amélioration continue**

Après chaque transformation :

SI Réel

↓

Nouvelle Cartographie

↓

CUz+1

↓

Nouvel Encodage

↓

ECUz+1

↓

Nouvelle Planification

Le système apprend continuellement.

**Objectif ultime**

Créer le premier système capable de :

-   comprendre un SI complet

-   mesurer sa qualité

-   simuler son évolution

-   planifier des transformations

-   exécuter ces transformations de manière contrôlée

-   apprendre des résultats obtenus

Autrement dit :

passer d\'une simple cartographie d\'entreprise à un véritable système autonome d\'urbanisation et de modernisation du SI.

Le projet combine :

-   Graph Neural Networks

-   Heterogeneous Graph Transformers

-   World Models de type JEPA

-   Reinforcement Learning

-   Planification latente

-   LLMs spécialisés

-   Jumeaux numériques

-   Architectures multi-agents Zero Trust

Pour transformer l\'architecture d\'entreprise en un espace d\'états navigable et optimisable, où chaque migration, refonte ou modernisation devient une transformation apprenable dans un espace latent commun.
