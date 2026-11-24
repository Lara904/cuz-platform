# services/api/tests/test_tenant_isolation.py
"""P2.14 — garde-fous d'isolation multi-tenant.

Écart corrigé par rapport au guide (voir DECISIONS.md, DEC-010) :
test_all_detection_rules_are_tenant_scoped du guide fait
`if "CYPHER" in source` (majuscules) sur le texte source des modules — aucun
module de ce repo ne contient jamais la sous-chaîne littérale "CYPHER" (le
champ est `cypher=`, en minuscules, dans chaque RuleSpec), donc cette
condition n'est jamais vraie et le test ne vérifie en réalité RIEN, pour
aucune règle, silencieusement vert. Il ne couvrait de toute façon que 5 des
8 modules réellement enregistrés par le moteur de détection
(packages.detection.runner.ALL_RULE_MODULES) : cis, iac, iac_tier1_extra et
shadow_it manquaient. Remplacé ici par une lecture directe de
RuleSpec.cypher (via rule.spec, exposé par make_rule) sur TOUTE règle
réellement enregistrée — plus robuste qu'une inspection de source, et
complet."""

import pytest

from packages.core.tenant_isolation import TenantIsolationError, assert_tenant_scoped_query
from packages.detection.runner import ALL_RULE_MODULES


def test_query_without_tenant_filter_raises():
    with pytest.raises(TenantIsolationError):
        assert_tenant_scoped_query("MATCH (n:CuzNode) RETURN n")


def test_query_with_tenant_filter_passes():
    assert assert_tenant_scoped_query("MATCH (n:CuzNode {tenant_id:$t}) RETURN n") is None


def test_all_detection_rules_are_tenant_scoped():
    """Garde-fou anti-fuite cross-tenant : vérifie que les règles Cypher
    RÉELLEMENT enregistrées (tous les modules de ALL_RULE_MODULES, pas une
    liste codée en dur dans le test) filtrent toutes par tenant_id, avant
    même d'exécuter une vraie requête Neo4j."""
    checked = 0
    for module in ALL_RULE_MODULES:
        for rule in module.RULES:
            checked += 1
            assert_tenant_scoped_query(rule.spec.cypher)
    assert checked >= 20, (
        "Moins de règles que prévu enregistrées — ALL_RULE_MODULES a-t-il changé ?"
    )


def test_all_detection_rules_are_tenant_scoped_covers_every_module():
    """Garde-fou contre une régression du test lui-même : si un module est un
    jour retiré de ALL_RULE_MODULES sans que ce test soit mis à jour, on veut
    le savoir plutôt que de valider silencieusement une couverture partielle
    (exactement le bug corrigé ci-dessus dans la version du guide)."""
    module_names = {m.__name__.rsplit(".", 1)[-1] for m in ALL_RULE_MODULES}
    assert module_names == {
        "network",
        "iam",
        "attack_path",
        "dora",
        "cis",
        "iac",
        "iac_tier1_extra",
        "shadow_it",
    }
