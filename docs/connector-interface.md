# Interface IConnector — CUz

## Principe fondamental

**Aucun connecteur ne peut écrire directement dans Neo4j.**

Tout connecteur produit des `RawEvents` vers le bus événementiel (Redpanda). La normalisation et l'entity resolution sont des étapes séparées. Ce principe est non-négociable et vérifié à la code review.

```
Source externe → Connecteur → RawEvent → Redpanda → Normalizer → Neo4j
```

---

## Interface abstraite

Tout connecteur doit hériter de `IConnector` et implémenter ses trois méthodes :

```python
# packages/core/interfaces/connector.py

class IConnector(ABC):

    def __init__(self, tenant_id: str, config: dict):
        self.tenant_id = tenant_id
        self.config = config

    @abstractmethod
    async def test_connection(self) -> bool:
        """Vérifie que la source est accessible.
        Retourne True si OK, lève une exception si non."""
        ...

    @abstractmethod
    async def pull_full(self) -> List[RawEvent]:
        """Scan complet de la source.
        Retourne tous les RawEvents.
        Doit être idempotent : même appel = mêmes events."""
        ...

    @abstractmethod
    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        """Souscription aux événements temps réel.
        Yield des RawEvents au fur et à mesure de leur réception."""
        ...
```

---

## Contrat des méthodes

### `test_connection()`

| Comportement attendu | Détail |
|---|---|
| Source accessible | Retourne `True` |
| Source inaccessible | Lève une exception (ex: `ConnectionError`) |
| Timeout | Lève une exception après le délai configuré |

Ne jamais retourner `False` silencieusement — toujours lever une exception avec un message explicite.

### `pull_full()`

| Comportement attendu | Détail |
|---|---|
| Résultat | `List[RawEvent]` — peut être vide si la source l'est |
| Idempotence | Deux appels identiques retournent le même nombre d'événements |
| Effet de bord | Aucun — ne modifie pas l'état de la source |
| `tenant_id` | Chaque RawEvent porte le `tenant_id` du connecteur |

### `subscribe_events()`

| Comportement attendu | Détail |
|---|---|
| Résultat | `AsyncIterator[RawEvent]` — yield au fil des événements |
| Durée | Boucle infinie jusqu'à annulation (webhooks, watch, polling) |
| Reconnexion | Le connecteur gère lui-même les reconnexions en cas de coupure |

---

## Structure d'un connecteur

Chaque connecteur est un sous-dossier indépendant dans `packages/connectors/` :

```
packages/connectors/
└── servicenow/
    ├── __init__.py
    ├── connector.py   # Implémente IConnector
    ├── mapper.py      # Mappe les données source → RawEvent
    └── tests/
        └── test_servicenow.py
```

Un connecteur = un dossier. Il n'impacte aucun autre package. La bibliothèque de connecteurs est réutilisée telle quelle pour chaque nouveau client — seuls les credentials changent.

---

## Règles de code review

Toute Pull Request contenant un connecteur est rejetée si :

1. Le connecteur importe `neo4j` directement
2. Le connecteur écrit dans Neo4j sans passer par Redpanda
3. `pull_full()` n'est pas idempotent
4. Un RawEvent ne porte pas de `tenant_id`
5. `test_connection()` retourne `False` au lieu de lever une exception

---

## Mock connecteur (tests)

Le mock connecteur dans `packages/core/interfaces/mock_connector.py` sert de référence d'implémentation et de base pour les tests de contrat :

```python
class MockConnector(IConnector):
    async def test_connection(self) -> bool:
        if self.should_fail:
            raise ConnectionError("Mock connection failure")
        return True

    async def pull_full(self) -> List[RawEvent]:
        # Retourne 2 RawEvents fictifs, idempotent
        ...

    async def subscribe_events(self) -> AsyncIterator[RawEvent]:
        # Yield 3 RawEvents fictifs
        ...
```

Les 5 tests de contrat dans `packages/core/tests/test_connector.py` valident :
1. `test_connection()` retourne `True` si la source est accessible
2. `test_connection()` lève une exception si la source est inaccessible
3. `pull_full()` retourne des `RawEvent` valides avec le bon `tenant_id`
4. `pull_full()` est idempotent (même résultat sur deux appels)
5. `subscribe_events()` yield des `RawEvent` valides