import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "./evaluator.js";
import type { PolicyDocument } from "./types.js";

describe("evaluatePolicy", () => {
  const policy: PolicyDocument = {
    version: 1,
    defaults: { action: "allow", on_error: "block" },
    rules: [
      {
        id: "block-tainted-sinks",
        when: { direction: "request", tool_class: "sink", taint: true },
        action: "block",
        reason: "tainted data entered a sink"
      },
      {
        id: "sanitize-untrusted",
        when: { direction: "response", trust: "untrusted", detector_score_gte: 0.4 },
        action: "sanitize"
      }
    ]
  };

  it("uses first-match-wins semantics", () => {
    const decision = evaluatePolicy(policy, {
      direction: "request",
      tool_class: "sink",
      taint: true
    });

    expect(decision.action).toBe("block");
    expect(decision.matchedRuleId).toBe("block-tainted-sinks");
  });

  it("falls back to the default action", () => {
    const decision = evaluatePolicy(policy, {
      direction: "request",
      tool_class: "pure",
      taint: false
    });

    expect(decision.action).toBe("allow");
  });
});
