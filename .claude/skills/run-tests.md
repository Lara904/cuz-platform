# Skill — /run-tests

## Usage

```
/run-tests [scope]
```

Exemples :
```
/run-tests core
/run-tests connectors
/run-tests servicenow
/run-tests all
```

## Commandes exécutées selon le scope

### `core`
```bash
pytest packages/core/tests/ -v
```

### `connectors` (tous)
```bash
pytest packages/connectors/ -v
```

### `<nom_connecteur>` (un seul)
```bash
pytest packages/connectors/<nom>/tests/ -v
```

### `integration`
```bash
pytest tests/ -v
```

### `attack-path`
```bash
bash tests/fixtures/ac8_scenarios.sh
```

### `all`
```bash
pytest packages/ tests/ -v
ruff check .
mypy packages/
```

## Après les tests

- Si des tests échouent, analyser l'erreur et proposer un correctif
- Ne jamais modifier les tests pour les faire passer — corriger le code
- Vérifier que `confidence_score` et `freshness_score` sont présents si erreur de validation Pydantic
