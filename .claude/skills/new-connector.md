# Skill — /new-connector

## Usage

```
/new-connector <nom> <NodeType> <description courte>
```

Exemple :
```
/new-connector terraform INFRASTRUCTURE "Ingère les ressources Terraform depuis tfstate"
```

## Ce que ce skill fait

Génère le squelette complet d'un nouveau connecteur CUz :

1. `packages/connectors/<nom>/__init__.py`
2. `packages/connectors/<nom>/connector.py` — avec `pull_full`, `pull_delta`, `health_check`
3. `packages/connectors/<nom>/mapper.py` — avec `map_node()` et optionnellement `map_edge()`
4. `packages/connectors/<nom>/tests/__init__.py`
5. `packages/connectors/<nom>/tests/test_connector.py`
6. `packages/connectors/<nom>/tests/test_mapper.py`

## Règles appliquées automatiquement

- `confidence_score` et `freshness_score` inclus sur tous les nœuds
- Publication dans Redpanda `cuz.raw.{tenant_id}`, jamais Neo4j direct
- `NormalizedEvent` avec champs `node` ET `edge`
- Variables d'env via `os.getenv()` + `load_dotenv()`
- Tests avec `unittest.mock.AsyncMock` pour la source externe

## Checklist post-génération

- [ ] Ajouter les variables d'env dans `.env.example`
- [ ] Vérifier que `NodeType.XXX` existe dans `packages/core/enums/`
- [ ] Lancer `pytest packages/connectors/<nom>/tests/ -v`
- [ ] Ajouter le connecteur dans `docker-compose.yml` si besoin
