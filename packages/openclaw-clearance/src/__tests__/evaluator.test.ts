import { describe, expect, it } from "vitest";
import { evaluate, type BundleModel, type BundleRule, type PolicyBundle } from "../evaluator";

function model(over: Partial<BundleModel> = {}): BundleModel {
  return {
    id: "m-flash",
    modelName: "DeepSeek V4 Flash",
    status: "approved",
    weakestRegion: "eu",
    servingVendorDpaSigned: true,
    ...over,
  };
}

function rule(over: Partial<BundleRule> = {}): BundleRule {
  return {
    id: "r1",
    agent_id: null,
    data_class: "personal_data",
    model_id: null,
    required_region: null,
    verdict: "allow",
    conditions: [],
    ...over,
  };
}

function bundle(over: Partial<PolicyBundle> = {}): PolicyBundle {
  return {
    bundleId: "pb_test",
    schemaVersion: 1,
    expiresAt: "2099-01-01T00:00:00Z",
    failMode: "open",
    rules: [rule()],
    models: [model()],
    ...over,
  };
}

describe("evaluate (parity with the platform evaluator)", () => {
  it("green when an allow rule covers the class", () => {
    expect(evaluate(bundle(), "m-flash", ["personal_data"]).light).toBe("green");
  });

  it("red on deny; yellow with no covering rule — never silent green", () => {
    expect(evaluate(bundle({ rules: [rule({ verdict: "deny" })] }), "m-flash", ["personal_data"]).light).toBe("red");
    const v = evaluate(bundle({ rules: [] }), "m-flash", ["personal_data"]);
    expect(v.light).toBe("yellow");
    expect(v.reasons.some((r) => r.code === "no_rule_for_class")).toBe(true);
  });

  it("resolves by case-insensitive name and yellows unknown models", () => {
    expect(evaluate(bundle(), "deepseek v4 flash", ["personal_data"]).light).toBe("green");
    const v = evaluate(bundle(), "gpt-unknown", ["personal_data"]);
    expect(v.light).toBe("yellow");
    expect(v.reasons.some((r) => r.code === "model_not_in_register")).toBe(true);
  });

  it("banned is red regardless; restricted/under_review floor at yellow", () => {
    expect(evaluate(bundle({ models: [model({ status: "banned" })] }), "m-flash", ["personal_data"]).light).toBe("red");
    expect(evaluate(bundle({ models: [model({ status: "restricted" })] }), "m-flash", ["personal_data"]).light).toBe("yellow");
  });

  it("agent rules replace org defaults; model-specific beats generic", () => {
    const agentWins = evaluate(
      bundle({ rules: [rule({ id: "org-deny", verdict: "deny" }), rule({ id: "agent-allow", agent_id: "a1", verdict: "allow" })] }),
      "m-flash",
      ["personal_data"],
      { agentId: "a1" },
    );
    expect(agentWins.light).toBe("green");
    expect(agentWins.matchedRuleIds).toEqual(["agent-allow"]);

    const modelWins = evaluate(
      bundle({ rules: [rule({ id: "generic-deny", verdict: "deny" }), rule({ id: "model-allow", model_id: "m-flash", verdict: "allow" })] }),
      "m-flash",
      ["personal_data"],
    );
    expect(modelWins.light).toBe("green");
  });

  it("most restrictive data class wins", () => {
    const v = evaluate(
      bundle({
        rules: [rule({ id: "pub", data_class: "public" }), rule({ id: "spec", data_class: "special_category", verdict: "deny" })],
      }),
      "m-flash",
      ["public", "special_category"],
    );
    expect(v.light).toBe("red");
  });

  it("conditions resolve against attestations + bundle vendor context", () => {
    const conditional = bundle({
      rules: [rule({ verdict: "conditional", conditions: ["literacy_required", "dpa_signed", "human_review"] })],
    });
    const unmet = evaluate(conditional, "m-flash", ["personal_data"]);
    expect(unmet.light).toBe("yellow");
    expect(unmet.unmetConditions.sort()).toEqual(["human_review", "literacy_required"]);

    const met = evaluate(conditional, "m-flash", ["personal_data"], {
      literacyCompleted: true,
      attestations: ["human_review"],
    });
    expect(met.light).toBe("green");
  });

  it("region constraints match the weakest link of the chain", () => {
    const v = evaluate(
      bundle({
        rules: [rule({ required_region: "eu" })],
        models: [model(), model({ id: "m-us", modelName: "US XL", weakestRegion: "us" })],
      }),
      "m-us",
      ["personal_data"],
    );
    expect(v.light).toBe("yellow");
  });

  it("suggests green approved alternatives, EU-first", () => {
    const v = evaluate(
      bundle({
        models: [
          model({ id: "m-target", modelName: "Target", status: "under_review" }),
          model({ id: "m-us", modelName: "US Alt", weakestRegion: "us" }),
          model({ id: "m-eu", modelName: "EU Alt", weakestRegion: "eu" }),
        ],
      }),
      "m-target",
      ["personal_data"],
    );
    expect(v.light).toBe("yellow");
    expect(v.recommendedAlternatives.map((a) => a.id)).toEqual(["m-eu", "m-us"]);
  });
});
