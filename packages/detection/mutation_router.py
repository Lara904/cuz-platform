# packages/detection/mutation_router.py
"""Détection réactive (P2.8) : une mutation du graphe ne relance que les règles concernées.

Remplace le `run_on_mutation()` provisoire de P1.8, qui relançait `run_all()`.
La table RULE_TRIGGERS dit, pour chaque règle Cypher, quelles mutations peuvent changer
son résultat. `test_mutation_router.py` vérifie qu'elle reste cohérente avec les requêtes
Cypher (toute règle enregistrée a une entrée, tout type cité dans la requête est couvert).

Limites assumées (cf. docs/known-limits.md) :
- une règle déclenchée s'évalue sur tout le tenant, pas seulement sur le nœud muté ;
- seules les règles Cypher sont routées : OPA et alertes cloud restent dans `run_all()` ;
- une mutation ne clôt pas un finding : comme `run_all()`, le routeur ne remonte que des
  findings ouverts.
"""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from packages.core.models.events import EventType, NormalizedEvent
from packages.detection.dedup import deduplicate
from packages.detection.models import Finding
from packages.detection.rules import RuleFn
from packages.detection.runner import ALL_RULE_MODULES, DetectionRunner

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Trigger:
    """Ce qui rend une règle pertinente pour une mutation."""

    node_types: frozenset[str] = frozenset()
    edge_types: frozenset[str] = frozenset()
    # Clés d'attributs/tags qui rendent la règle pertinente quel que soit le type du nœud
    node_props: frozenset[str] = frozenset()
    # Règle sur « tout actif » : pertinente à chaque nouveau nœud
    on_node_created: bool = False
    # Règle pilotée par le temps (fraîcheur), pas par une mutation : scan périodique seulement
    periodic_only: bool = False


def _t(*names: str) -> frozenset[str]:
    return frozenset(names)


RULE_TRIGGERS: dict[str, Trigger] = {
    "NET-001": Trigger(node_types=_t("SERVER", "CONTAINER", "CLUSTER")),
    "STORAGE-PUBLIC-001": Trigger(node_types=_t("STORAGE")),
    "K8S-PRIV-001": Trigger(node_types=_t("CONTAINER")),
    "IAM-001": Trigger(node_types=_t("USER")),
    "OAUTH-LATERAL-001": Trigger(
        node_types=_t("SERVICE_ACCOUNT", "ROLE", "STORAGE"),
        edge_types=_t("HAS_ROLE", "ALLOWS"),
    ),
    "ATTACK-PATH-001-PARTIAL": Trigger(
        node_types=_t("USER", "REPOSITORY", "VULNERABILITY"),
        edge_types=_t("OWNS", "DEPENDS_ON", "AFFECTS"),
    ),
    "DORA-THIRD-PARTY-001": Trigger(node_types=_t("THIRD_PARTY"), edge_types=_t("SUPPORTS")),
    "IAC-DRIFT-001": Trigger(node_types=_t("STORAGE", "CONTAINER"), node_props=_t("iac_managed")),
    "SHADOW-IT-001": Trigger(on_node_created=True),
    "CIS-001": Trigger(node_props=_t("tls_cert_expired")),
    "CIS-002": Trigger(node_props=_t("critical_port_exposed", "is_public")),
    "CIS-003": Trigger(node_types=_t("APPLICATION", "API", "THIRD_PARTY")),
    "CIS-004": Trigger(periodic_only=True),  # freshness_score < 0.2 : décroissance, pas mutation
    "CIS-005": Trigger(node_types=_t("GROUP", "USER"), edge_types=_t("MEMBER_OF")),
    "CIS-006": Trigger(node_types=_t("SERVICE_ACCOUNT")),
    "CIS-007": Trigger(node_types=_t("DATABASE")),
    "CIS-008": Trigger(node_types=_t("API")),
    "CIS-009": Trigger(node_types=_t("CONTAINER")),
    "CIS-010": Trigger(node_props=_t("plaintext_secret")),
    "CIS-011": Trigger(node_types=_t("ROLE")),
    "CIS-012": Trigger(node_types=_t("API")),
}


def registered_rules() -> dict[str, RuleFn]:
    """Toutes les règles Cypher enregistrées, par rule_id (même registre que run_all)."""
    return {
        fn.spec.rule_id: fn  # type: ignore[attr-defined]
        for module in ALL_RULE_MODULES
        for fn in module.RULES
    }


def _is_relevant(trigger: Trigger, event: NormalizedEvent) -> bool:
    if trigger.periodic_only:
        return False
    if event.edge is not None and event.edge.edge_type.value in trigger.edge_types:
        return True
    node = event.node
    if node is None:
        return False
    if node.node_type.value in trigger.node_types:
        return True
    if trigger.on_node_created and event.event_type == EventType.NODE_CREATED:
        return True
    return bool(trigger.node_props & (set(node.attributes) | set(node.tags)))


@dataclass(frozen=True)
class BatchResult:
    findings: list[Finding]
    failed_rules: list[str]
    rules_run: int


class MutationRouter:
    def __init__(self, runner: DetectionRunner | None = None) -> None:
        self.runner = runner or DetectionRunner()
        self._rules = registered_rules()
        self._mutations = 0
        self._queries = 0

    @property
    def full_scan_queries(self) -> int:
        """Requêtes Cypher d'un scan complet : une par règle enregistrée."""
        return len(self._rules)

    def rules_for_event(self, event: NormalizedEvent) -> list[RuleFn]:
        return [
            self._rules[rule_id]
            for rule_id, trigger in sorted(RULE_TRIGGERS.items())
            if rule_id in self._rules and _is_relevant(trigger, event)
        ]

    def run_on_mutations(self, tenant_id: str, events: Sequence[NormalizedEvent]) -> BatchResult:
        """Évalue un lot de mutations : l'union des règles routées, chacune UNE seule fois.

        Les règles s'évaluent sur tout le tenant : lancer la même règle pour chaque mutation d'un
        rescan (des milliers) n'apporterait aucun finding de plus. Les échecs de règle sont
        remontés dans `failed_rules` pour que l'appelant ne valide pas un lot non évalué.
        """
        for event in events:
            if event.tenant_id != tenant_id:  # isolation tenant : jamais d'évaluation croisée
                raise ValueError(f"événement du tenant {event.tenant_id} routé vers {tenant_id}")
        rules: dict[str, RuleFn] = {}
        for event in events:
            for rule_fn in self.rules_for_event(event):
                rules[rule_fn.spec.rule_id] = rule_fn  # type: ignore[attr-defined]
        self._mutations += len(events)
        self._queries += len(rules)
        findings: list[Finding] = []
        failed: list[str] = []
        if rules:
            with self.runner.driver.session() as session:
                for rule_id, rule_fn in rules.items():
                    try:
                        findings.extend(rule_fn(session, tenant_id))
                    except Exception as exc:  # une règle en échec ne bloque pas les autres
                        failed.append(rule_id)
                        logger.error("tenant=%s rule %s failed: %s", tenant_id, rule_id, exc)
        if findings:
            self.runner._fill_confidence(tenant_id, findings)
        return BatchResult(
            findings=deduplicate(findings), failed_rules=failed, rules_run=len(rules)
        )

    def run_on_mutation(self, tenant_id: str, event: NormalizedEvent) -> list[Finding]:
        return self.run_on_mutations(tenant_id, [event]).findings

    def query_reduction_pct(self) -> float:
        """Réduction du nombre de requêtes Cypher vs un scan complet à chaque mutation,
        moyennée sur toutes les mutations traitées (0.0 tant qu'aucune n'a été traitée)."""
        if self._mutations == 0:
            return 0.0
        full = self._mutations * self.full_scan_queries
        return round(100 * (1 - self._queries / full), 1)

    def reduction_for(self, events: Iterable[NormalizedEvent]) -> float:
        """Réduction attendue sur un échantillon d'événements, sans interroger Neo4j."""
        events = list(events)
        if not events:
            return 0.0
        queries = sum(len(self.rules_for_event(e)) for e in events)
        return round(100 * (1 - queries / (len(events) * self.full_scan_queries)), 1)


def affected_rule_ids(event: NormalizedEvent) -> list[str]:
    """Identifiants des règles routées pour cet événement (diagnostic, sans runner)."""
    return [
        rule_id
        for rule_id, trigger in sorted(RULE_TRIGGERS.items())
        if _is_relevant(trigger, event)
    ]


__all__ = [
    "RULE_TRIGGERS",
    "BatchResult",
    "MutationRouter",
    "Trigger",
    "affected_rule_ids",
    "registered_rules",
]
