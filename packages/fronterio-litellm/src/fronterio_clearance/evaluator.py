"""Local policy-bundle evaluator.

A faithful port of Fronterio's deterministic routing-policy evaluator, operating
on the signed policy bundle (GET /api/v1/model-use/bundle). Pure, offline,
sub-millisecond — the enforcement point runs in YOUR runtime; Fronterio only
signed the rulebook.

Semantics (identical to the platform evaluator):
- agent-specific rules REPLACE org defaults for a data class
- model-specific rules beat generic rules within a scope
- deny > conditional > allow; the most restrictive data class wins
- conditional resolves green only when every named condition is met
- no covering rule -> yellow "no_rule_for_class" (never a silent green)
- banned models are red regardless; restricted/under_review floor at yellow
- region constraints match against the model's weakest-link residency
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

REGION_RANK = {"on_prem": 0, "eu": 1, "eea": 2, "uk": 3, "us": 4, "other": 5}

GREEN, YELLOW, RED = "green", "yellow", "red"
_LIGHT_RANK = {GREEN: 0, YELLOW: 1, RED: 2}


@dataclass
class Reason:
    code: str
    data_class: Optional[str] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict = {"code": self.code}
        if self.data_class:
            out["dataClass"] = self.data_class
        if self.rule_id:
            out["ruleId"] = self.rule_id
        return out


@dataclass
class Verdict:
    light: str
    reasons: list[Reason] = field(default_factory=list)
    unmet_conditions: list[str] = field(default_factory=list)
    matched_rule_ids: list[str] = field(default_factory=list)
    recommended_alternatives: list[dict] = field(default_factory=list)


def _resolve_model(models: list[dict], ref: str) -> Optional[dict]:
    for m in models:
        if m.get("id") == ref:
            return m
    needle = ref.strip().lower()
    for m in models:
        if str(m.get("modelName", "")).strip().lower() == needle:
            return m
    return None


def _satisfies_region(model: Optional[dict], required: str) -> bool:
    if model is None:
        return False
    weakest = model.get("weakestRegion", "other")
    return REGION_RANK.get(weakest, 5) <= REGION_RANK.get(required, 5)


def _rule_matches(rule: dict, data_class: str, model: Optional[dict]) -> bool:
    if rule.get("data_class") != data_class:
        return False
    if rule.get("model_id"):
        if model is None or rule["model_id"] != model.get("id"):
            return False
    if rule.get("required_region"):
        if not _satisfies_region(model, rule["required_region"]):
            return False
    return True


def _unmet(conditions: Iterable[str], model: Optional[dict],
           literacy_completed: bool, attestations: set[str]) -> list[str]:
    unmet = []
    for condition in conditions:
        if condition == "literacy_required":
            ok = literacy_completed
        elif condition == "dpa_signed":
            ok = bool(model and model.get("servingVendorDpaSigned"))
        elif condition in ("human_review", "anonymised_only"):
            ok = condition in attestations
        else:
            ok = False
        if not ok:
            unmet.append(condition)
    return unmet


def _evaluate_class(rules: list[dict], data_class: str, agent_id: Optional[str],
                    model: Optional[dict], literacy_completed: bool,
                    attestations: set[str]) -> tuple[str, Reason, list[str], list[str]]:
    agent_rules = [r for r in rules
                   if agent_id and r.get("agent_id") == agent_id
                   and _rule_matches(r, data_class, model)]
    scoped = agent_rules or [r for r in rules
                             if r.get("agent_id") is None
                             and _rule_matches(r, data_class, model)]
    if not scoped:
        return YELLOW, Reason("no_rule_for_class", data_class), [], []

    model_specific = [r for r in scoped if r.get("model_id")]
    effective = model_specific or scoped

    deny = next((r for r in effective if r.get("verdict") == "deny"), None)
    if deny:
        return RED, Reason("denied_by_rule", data_class, deny.get("id")), [], [deny.get("id")]

    conditional = [r for r in effective if r.get("verdict") == "conditional"]
    if conditional:
        conditions: list[str] = []
        for r in conditional:
            for c in r.get("conditions") or []:
                if c not in conditions:
                    conditions.append(c)
        unmet = _unmet(conditions, model, literacy_completed, attestations)
        rule_ids = [r.get("id") for r in conditional]
        if unmet:
            return YELLOW, Reason("conditions_unmet", data_class, conditional[0].get("id")), unmet, rule_ids
        return GREEN, Reason("allowed", data_class, conditional[0].get("id")), [], rule_ids

    allow = [r for r in effective if r.get("verdict") == "allow"]
    rule_id = allow[0].get("id") if allow else None
    return GREEN, Reason("allowed", data_class, rule_id), [], [r.get("id") for r in allow]


def _evaluate_against(bundle: dict, model: Optional[dict], data_classes: list[str],
                      agent_id: Optional[str], literacy_completed: bool,
                      attestations: set[str]) -> Verdict:
    if model is not None and model.get("status") == "banned":
        return Verdict(RED, [Reason("model_banned")])

    rules = bundle.get("rules") or []
    lights: list[str] = []
    verdict = Verdict(GREEN)
    for data_class in data_classes:
        light, reason, unmet, rule_ids = _evaluate_class(
            rules, data_class, agent_id, model, literacy_completed, attestations)
        lights.append(light)
        verdict.reasons.append(reason)
        for c in unmet:
            if c not in verdict.unmet_conditions:
                verdict.unmet_conditions.append(c)
        for rid in rule_ids:
            if rid and rid not in verdict.matched_rule_ids:
                verdict.matched_rule_ids.append(rid)

    if model is None:
        lights.append(YELLOW)
        verdict.reasons.append(Reason("model_not_in_register"))
    elif model.get("status") == "restricted":
        lights.append(YELLOW)
        verdict.reasons.append(Reason("model_restricted"))
    elif model.get("status") == "under_review":
        lights.append(YELLOW)
        verdict.reasons.append(Reason("model_under_review"))

    verdict.light = max(lights, key=lambda l: _LIGHT_RANK[l]) if lights else GREEN
    return verdict


def evaluate(bundle: dict, model_ref: str, data_classes: list[str],
             agent_id: Optional[str] = None, literacy_completed: bool = False,
             attestations: Optional[Iterable[str]] = None) -> Verdict:
    """Evaluate a proposed model use against a policy bundle. Pure."""
    attest = set(attestations or [])
    models: list[dict] = bundle.get("models") or []
    model = _resolve_model(models, model_ref)
    verdict = _evaluate_against(bundle, model, data_classes, agent_id,
                                literacy_completed, attest)

    if verdict.light != GREEN:
        alternatives: list[dict[str, Any]] = []
        for candidate in models:
            if candidate.get("status") != "approved":
                continue
            if model is not None and candidate.get("id") == model.get("id"):
                continue
            alt = _evaluate_against(bundle, candidate, data_classes, agent_id,
                                    literacy_completed, attest)
            if alt.light == GREEN:
                alternatives.append({
                    "id": candidate.get("id"),
                    "modelName": candidate.get("modelName"),
                    "weakestRegion": candidate.get("weakestRegion", "other"),
                })
        alternatives.sort(key=lambda a: (REGION_RANK.get(a["weakestRegion"], 5),
                                         str(a["modelName"])))
        verdict.recommended_alternatives = alternatives[:3]

    return verdict
