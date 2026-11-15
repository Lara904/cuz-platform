# CUz — Cartographie Unifiée du SI
## Contexte projet pour Claude Code

**Développeuse :** Lara (solo, Fedora, Python 3.12, Docker Compose actif, venv activé)  
**Dépôt :** Lara904/cuz-platform  
**Objectif Phase 1 :** détecter automatiquement ATTACK-PATH-001 (djana.dev sans MFA → repo backend → CVE-2022-24999 → bucket public)

---

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Langage | Python 3.12 |
| API | FastAPI + JWT + RBAC 4 rôles |
| Graphe | Neo4j |
| Message bus | Redpanda (topics `cuz.raw.{tenant_id}`, `cuz.normalized.{tenant_id}`) |
| Base relationnelle | PostgreSQL |
| Cache | Redis |
| Vecteurs | Qdrant |
| Politiques | OPA |
| Infra locale | Docker Compose + k3d |
| Tests | pytest |
| CI | GitHub Actions |

---

## RÈGLES NON NÉGOCIABLES

1. **Aucun connecteur n'écrit directement dans Neo4j.** Tout transit par Redpanda topic `cuz.raw.{tenant_id}`.
2. **Tout nœud et toute arête porte `confidence_score` ET `freshness_score`.** Sans exception.
3. **Aucune action automatique sur un nœud dont `confidence_score < 0.7`.**
4. **L'audit trail est immuable** — PostgreSQL append-only, aucune suppression de log.
5. **Un connecteur = un dossier dans `packages/connectors/`.** Hérite de `IConnector`. Contient `connector.py`, `mapper.py`, `tests/`.

---

## Architecture

```
~/projets/cuz-platform/
├── packages/
│   ├── core/
│   │   ├── models/        # CuzNode, CuzEdge, RawEvent, NormalizedEvent
│   │   ├── enums/         # NodeType, EdgeType
│   │   ├── scoring/       # compute_confidence(), compute_freshness()
│   │   └── interfaces/    # IConnector
│   └── connectors/
│       ├── servicenow/    # ✅ P1.1
│       ├── minio/         # ✅ P1.2
│       ├── entra_id/      # ✅ P1.3
│       └── gitea/         # ✅ P1.4
├── ingestion/             # ❌ À créer P1.5
├── entity-resolution/     # ❌ À créer P1.6
├── graph/                 # ❌ À créer P1.7
├── detection/             # ❌ À créer P1.8
├── services/
├── infra/
└── tests/fixtures/
    ├── acmecorp.tfstate
    └── acmecorp_cves.json  # CVE-2022-24999 (CVSS 9.8)
```

---

## Modèles clés

### CuzNode
```python
class CuzNode(BaseModel):
    id: str                    # format: "{connector}:{external_id}"
    type: NodeType
    tenant_id: str
    label: str
    confidence_score: float    # OBLIGATOIRE
    freshness_score: float     # OBLIGATOIRE
    sources: list[str]
    attributes: dict[str, Any]
    tags: dict[str, str]
```

### NormalizedEvent (FIX-2 inclus)
```python
class NormalizedEvent(BaseModel):
    node: CuzNode | None       # obligatoire dès V1
    edge: CuzEdge | None       # obligatoire dès V1 — NE PAS OUBLIER
    tenant_id: str
    source_connector: str
    timestamp: datetime
```

---

## Statut Phase 1

| Phase | Description | Statut |
|-------|-------------|--------|
| P0 | Core, API, infra | ✅ |
| P1.1 | Connecteur ServiceNow | ✅ (FIX-1 à appliquer) |
| P1.2 | Connecteur MinIO | ✅ |
| P1.3 | Connecteur Entra ID | ✅ |
| P1.4 | Connecteur Gitea | ✅ |
| P1.5 | Pipeline ingestion + Normalizer | ❌ |
| P1.6 | Entity Resolution | ❌ |
| P1.7 | Graph Writer | ❌ |
| P1.8 | Moteur règles Cypher | ❌ |
| P1.9–P1.15 | Dashboard, API, scoring, DORA | ❌ |
| P1.16 | Réconciliation métier↔IT | ❌ |
| P1.17 | DICT criticité | ❌ |
| P1.18 | Shadow IT mesurable | ❌ |

---

## ⚠️ CORRECTIFS BLOQUANTS avant P1.5

### FIX-1 — servicenow/mapper.py L8-14
```python
# AVANT (bugué)
node_type = NodeType.APPLICATION
# APRÈS
node_type = NodeType.THIRD_PARTY if rec.get("u_vendor_type") == "third_party" else NodeType.APPLICATION
```

### FIX-2 — NormalizedEvent doit porter `edge`
`map_repo_dependency_edge()` produit une CuzEdge que rien ne publie. Ajouter `edge: CuzEdge | None` dès la V1.

### FIX-3 — Propriétés Neo4j natives (anticiper P1.7)
Promouvoir `has_mfa`, `is_public`, `privileged`, `criticality`, `owner` en propriétés top-level Neo4j en plus du blob `attributes`. Ne jamais filtrer avec `CONTAINS` sur du JSON.

---

## ATTACK-PATH-001

5 maillons à détecter automatiquement :
1. `djana.dev` → `has_mfa: false`
2. `djana.dev` → HAS_ACCESS → `backend` (repo acmecorp)
3. `backend` → DEPENDS_ON → `qs@6.5.2` (CVE-2022-24999, CVSS 9.8)
4. `qs@6.5.2` → pod `legacy-job` (`privileged: true`)
5. `legacy-job` → HAS_ACCESS → `acmecorp-public` (`is_public: true`)

---

## Commandes utiles

```bash
docker compose ps                        # 6 services healthy
pytest packages/core/tests/ -v          # 50 tests core
pytest packages/connectors/ -v          # tests connecteurs
pytest tests/ -v                        # intégration
bash tests/fixtures/ac8_scenarios.sh    # vérif attack path
ruff check .
mypy packages/
```

---

## Conventions

- Imports absolus : `from packages.core.models import CuzNode`
- Tout typé, mypy strict
- `structlog` avec `tenant_id` dans chaque log
- Secrets uniquement via `.env` + `python-dotenv`
- `async/await` pour tous les I/O
- `attributes["criticality"] = {"D":1-4,"I":1-4,"C":1-4,"T":1-4}` (échelle DICT)
