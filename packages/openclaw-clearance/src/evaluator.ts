/**
 * Local policy-bundle evaluator — a faithful port of Fronterio's deterministic
 * routing-policy evaluator, operating on the signed policy bundle
 * (GET /api/v1/model-use/bundle). Pure, offline, sub-millisecond.
 *
 * Semantics (identical to the platform evaluator):
 * - agent-specific rules REPLACE org defaults for a data class
 * - model-specific rules beat generic rules within a scope
 * - deny > conditional > allow; the most restrictive data class wins
 * - conditional resolves green only when every named condition is met
 * - no covering rule → yellow "no_rule_for_class" (never a silent green)
 * - banned models are red regardless; restricted/under_review floor at yellow
 * - region constraints match against the model's weakest-link residency
 */

export type TrafficLight = "green" | "yellow" | "red";

export interface BundleRule {
  id: string;
  agent_id: string | null;
  data_class: string;
  model_id: string | null;
  required_region: string | null;
  verdict: "allow" | "conditional" | "deny";
  conditions: string[];
}

export interface BundleModel {
  id: string;
  modelName: string;
  status: "approved" | "restricted" | "banned" | "under_review";
  weakestRegion: string;
  servingVendorDpaSigned: boolean;
}

export interface PolicyBundle {
  bundleId: string;
  schemaVersion: number;
  organizationId?: string;
  issuedAt?: string;
  expiresAt: string;
  failMode: "open" | "closed";
  rules: BundleRule[];
  models: BundleModel[];
}

export interface Reason {
  code: string;
  dataClass?: string;
  ruleId?: string;
}

export interface Verdict {
  light: TrafficLight;
  reasons: Reason[];
  unmetConditions: string[];
  matchedRuleIds: string[];
  recommendedAlternatives: { id: string; modelName: string; weakestRegion: string }[];
}

export interface EvaluateOptions {
  agentId?: string | null;
  literacyCompleted?: boolean;
  attestations?: string[];
}

const REGION_RANK: Record<string, number> = {
  on_prem: 0, eu: 1, eea: 2, uk: 3, us: 4, other: 5,
};
const LIGHT_RANK: Record<TrafficLight, number> = { green: 0, yellow: 1, red: 2 };

function resolveModel(models: BundleModel[], ref: string): BundleModel | null {
  const byId = models.find((m) => m.id === ref);
  if (byId) return byId;
  const needle = ref.trim().toLowerCase();
  return models.find((m) => m.modelName.trim().toLowerCase() === needle) ?? null;
}

function satisfiesRegion(model: BundleModel | null, required: string): boolean {
  if (!model) return false;
  return (REGION_RANK[model.weakestRegion] ?? 5) <= (REGION_RANK[required] ?? 5);
}

function ruleMatches(rule: BundleRule, dataClass: string, model: BundleModel | null): boolean {
  if (rule.data_class !== dataClass) return false;
  if (rule.model_id && (!model || rule.model_id !== model.id)) return false;
  if (rule.required_region && !satisfiesRegion(model, rule.required_region)) return false;
  return true;
}

function unmetFor(
  conditions: string[],
  model: BundleModel | null,
  literacyCompleted: boolean,
  attestations: Set<string>,
): string[] {
  return conditions.filter((condition) => {
    switch (condition) {
      case "literacy_required": return !literacyCompleted;
      case "dpa_signed": return !model?.servingVendorDpaSigned;
      case "human_review":
      case "anonymised_only": return !attestations.has(condition);
      default: return true;
    }
  });
}

function evaluateClass(
  rules: BundleRule[],
  dataClass: string,
  agentId: string | null,
  model: BundleModel | null,
  literacyCompleted: boolean,
  attestations: Set<string>,
): { light: TrafficLight; reason: Reason; unmet: string[]; ruleIds: string[] } {
  const agentRules = agentId
    ? rules.filter((r) => r.agent_id === agentId && ruleMatches(r, dataClass, model))
    : [];
  const scoped = agentRules.length > 0
    ? agentRules
    : rules.filter((r) => r.agent_id === null && ruleMatches(r, dataClass, model));

  if (scoped.length === 0) {
    return { light: "yellow", reason: { code: "no_rule_for_class", dataClass }, unmet: [], ruleIds: [] };
  }

  const modelSpecific = scoped.filter((r) => r.model_id !== null);
  const effective = modelSpecific.length > 0 ? modelSpecific : scoped;

  const deny = effective.find((r) => r.verdict === "deny");
  if (deny) {
    return { light: "red", reason: { code: "denied_by_rule", dataClass, ruleId: deny.id }, unmet: [], ruleIds: [deny.id] };
  }

  const conditional = effective.filter((r) => r.verdict === "conditional");
  if (conditional.length > 0) {
    const conditions = [...new Set(conditional.flatMap((r) => r.conditions))];
    const unmet = unmetFor(conditions, model, literacyCompleted, attestations);
    const ruleIds = conditional.map((r) => r.id);
    if (unmet.length > 0) {
      return { light: "yellow", reason: { code: "conditions_unmet", dataClass, ruleId: conditional[0].id }, unmet, ruleIds };
    }
    return { light: "green", reason: { code: "allowed", dataClass, ruleId: conditional[0].id }, unmet: [], ruleIds };
  }

  const allow = effective.filter((r) => r.verdict === "allow");
  return {
    light: "green",
    reason: { code: "allowed", dataClass, ruleId: allow[0]?.id },
    unmet: [],
    ruleIds: allow.map((r) => r.id),
  };
}

function evaluateAgainst(
  bundle: PolicyBundle,
  model: BundleModel | null,
  dataClasses: string[],
  options: EvaluateOptions,
): Omit<Verdict, "recommendedAlternatives"> {
  if (model && model.status === "banned") {
    return { light: "red", reasons: [{ code: "model_banned" }], unmetConditions: [], matchedRuleIds: [] };
  }

  const attestations = new Set(options.attestations ?? []);
  const literacy = options.literacyCompleted === true;
  const agentId = options.agentId ?? null;

  const lights: TrafficLight[] = [];
  const reasons: Reason[] = [];
  const unmetConditions: string[] = [];
  const matchedRuleIds: string[] = [];

  for (const dataClass of dataClasses) {
    const outcome = evaluateClass(bundle.rules, dataClass, agentId, model, literacy, attestations);
    lights.push(outcome.light);
    reasons.push(outcome.reason);
    for (const c of outcome.unmet) if (!unmetConditions.includes(c)) unmetConditions.push(c);
    for (const id of outcome.ruleIds) if (id && !matchedRuleIds.includes(id)) matchedRuleIds.push(id);
  }

  if (!model) {
    lights.push("yellow");
    reasons.push({ code: "model_not_in_register" });
  } else if (model.status === "restricted") {
    lights.push("yellow");
    reasons.push({ code: "model_restricted" });
  } else if (model.status === "under_review") {
    lights.push("yellow");
    reasons.push({ code: "model_under_review" });
  }

  const light = lights.reduce<TrafficLight>(
    (worst, l) => (LIGHT_RANK[l] > LIGHT_RANK[worst] ? l : worst),
    "green",
  );
  return { light, reasons, unmetConditions, matchedRuleIds };
}

/** Evaluate a proposed model use against a policy bundle. Pure. */
export function evaluate(
  bundle: PolicyBundle,
  modelRef: string,
  dataClasses: string[],
  options: EvaluateOptions = {},
): Verdict {
  const model = resolveModel(bundle.models, modelRef);
  const base = evaluateAgainst(bundle, model, dataClasses, options);

  let recommendedAlternatives: Verdict["recommendedAlternatives"] = [];
  if (base.light !== "green") {
    recommendedAlternatives = bundle.models
      .filter((m) => m.status === "approved" && m.id !== model?.id)
      .filter((m) => evaluateAgainst(bundle, m, dataClasses, options).light === "green")
      .map((m) => ({ id: m.id, modelName: m.modelName, weakestRegion: m.weakestRegion }))
      .sort(
        (a, b) =>
          (REGION_RANK[a.weakestRegion] ?? 5) - (REGION_RANK[b.weakestRegion] ?? 5) ||
          a.modelName.localeCompare(b.modelName),
      )
      .slice(0, 3);
  }

  return { ...base, recommendedAlternatives };
}
