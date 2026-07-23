"""Evaluator parity tests — mirror the platform evaluator's test suite."""

from fronterio_clearance.evaluator import evaluate


def bundle(**over):
    base = {
        "bundleId": "pb_test",
        "schemaVersion": 1,
        "failMode": "open",
        "rules": [rule()],
        "models": [model()],
    }
    base.update(over)
    return base


def model(**over):
    base = {
        "id": "m-flash",
        "modelName": "DeepSeek V4 Flash",
        "status": "approved",
        "weakestRegion": "eu",
        "servingVendorDpaSigned": True,
    }
    base.update(over)
    return base


def rule(**over):
    base = {
        "id": "r1",
        "agent_id": None,
        "data_class": "personal_data",
        "model_id": None,
        "required_region": None,
        "verdict": "allow",
        "conditions": [],
    }
    base.update(over)
    return base


def test_green_when_allow_rule_covers_class():
    v = evaluate(bundle(), "m-flash", ["personal_data"])
    assert v.light == "green"
    assert v.reasons[0].code == "allowed"


def test_red_when_deny_rule_matches():
    v = evaluate(bundle(rules=[rule(verdict="deny")]), "m-flash", ["personal_data"])
    assert v.light == "red"
    assert v.reasons[0].code == "denied_by_rule"


def test_yellow_with_no_covering_rule_never_silent_green():
    v = evaluate(bundle(rules=[]), "m-flash", ["personal_data"])
    assert v.light == "yellow"
    assert any(r.code == "no_rule_for_class" for r in v.reasons)


def test_yellow_when_model_not_in_bundle():
    v = evaluate(bundle(), "unknown-model", ["personal_data"])
    assert v.light == "yellow"
    assert any(r.code == "model_not_in_register" for r in v.reasons)


def test_resolves_model_by_case_insensitive_name():
    v = evaluate(bundle(), "deepseek v4 flash", ["personal_data"])
    assert v.light == "green"


def test_banned_model_is_red_regardless_of_rules():
    v = evaluate(bundle(models=[model(status="banned")]), "m-flash", ["personal_data"])
    assert v.light == "red"
    assert v.reasons[0].code == "model_banned"


def test_restricted_and_under_review_floor_at_yellow():
    for status in ("restricted", "under_review"):
        v = evaluate(bundle(models=[model(status=status)]), "m-flash", ["personal_data"])
        assert v.light == "yellow"


def test_agent_rules_replace_org_defaults():
    rules = [rule(id="org-deny", verdict="deny"),
             rule(id="agent-allow", agent_id="agent-1", verdict="allow")]
    v = evaluate(bundle(rules=rules), "m-flash", ["personal_data"], agent_id="agent-1")
    assert v.light == "green"
    assert v.matched_rule_ids == ["agent-allow"]


def test_model_specific_beats_generic():
    rules = [rule(id="generic-deny", verdict="deny"),
             rule(id="model-allow", model_id="m-flash", verdict="allow")]
    v = evaluate(bundle(rules=rules), "m-flash", ["personal_data"])
    assert v.light == "green"


def test_most_restrictive_class_wins():
    rules = [rule(id="pub", data_class="public", verdict="allow"),
             rule(id="spec", data_class="special_category", verdict="deny")]
    v = evaluate(bundle(rules=rules), "m-flash", ["public", "special_category"])
    assert v.light == "red"


def test_conditions_resolve_against_attestations_and_bundle_context():
    conditional = rule(verdict="conditional",
                       conditions=["literacy_required", "dpa_signed", "human_review"])
    b = bundle(rules=[conditional])
    v = evaluate(b, "m-flash", ["personal_data"])
    assert v.light == "yellow"
    assert set(v.unmet_conditions) == {"literacy_required", "human_review"}

    v = evaluate(b, "m-flash", ["personal_data"],
                 literacy_completed=True, attestations=["human_review"])
    assert v.light == "green"


def test_dpa_condition_reads_bundle_vendor_context():
    b = bundle(rules=[rule(verdict="conditional", conditions=["dpa_signed"])],
               models=[model(servingVendorDpaSigned=False)])
    v = evaluate(b, "m-flash", ["personal_data"])
    assert v.light == "yellow"
    assert v.unmet_conditions == ["dpa_signed"]


def test_region_constraint_matches_weakest_link():
    eu_only = rule(required_region="eu")
    us_model = model(id="m-us", modelName="US XL", weakestRegion="us")
    v = evaluate(bundle(rules=[eu_only], models=[model(), us_model]),
                 "m-us", ["personal_data"])
    assert v.light == "yellow"  # rule unmatched -> no rule for class


def test_alternatives_are_green_approved_models_eu_first():
    us_alt = model(id="m-us", modelName="US Alt", weakestRegion="us")
    eu_alt = model(id="m-eu", modelName="EU Alt", weakestRegion="eu")
    target = model(id="m-target", modelName="Target", status="under_review")
    v = evaluate(bundle(models=[target, us_alt, eu_alt]), "m-target", ["personal_data"])
    assert v.light == "yellow"
    assert [a["id"] for a in v.recommended_alternatives] == ["m-eu", "m-us"]
