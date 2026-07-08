import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "./evaluator.js";
import { loadPolicyFile } from "./loader.js";
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

  it("sanitizes semi-trusted tools/call output with detector hits in the shipped default policy", async () => {
    const shippedDefault = await loadPolicyFile(join(process.cwd(), "policies", "default.yaml"));

    const decision = evaluatePolicy(shippedDefault, {
      direction: "response",
      method: "tools/call",
      trust: "semi",
      detector_score: 0.45,
      labels: ["ignore-instructions"]
    });

    expect(decision.action).toBe("sanitize");
    expect(decision.matchedRuleId).toBe("sanitize-suspicious-untrusted-output");
  });

  it("keeps strict tainted-sink blocking trust-agnostic and sanitizes strong response signals", async () => {
    const shippedDefault = await loadPolicyFile(join(process.cwd(), "policies", "default.yaml"));
    const shippedStrict = await loadPolicyFile(join(process.cwd(), "policies", "strict.yaml"));

    expect(evaluatePolicy(shippedDefault, {
      direction: "request",
      method: "tools/call",
      trust: "trusted",
      tool_class: "sink",
      taint: true
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-tainted-sink"
    });

    expect(evaluatePolicy(shippedStrict, {
      direction: "response",
      method: "tools/call",
      trust: "semi",
      detector_score: 0.8
    })).toMatchObject({
      action: "sanitize",
      matchedRuleId: "sanitize-strong-injection-any-trust"
    });

    expect(evaluatePolicy(shippedStrict, {
      direction: "request",
      method: "tools/call",
      trust: "trusted",
      tool_class: "sink",
      taint: true
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-tainted-sink"
    });
  });

  it("uses approval for tainted sinks in the shipped interactive preset only", async () => {
    const interactive = await loadPolicyFile(join(process.cwd(), "policies", "interactive.yaml"));

    expect(evaluatePolicy(interactive, {
      direction: "request",
      method: "tools/call",
      trust: "trusted",
      tool_class: "sink",
      taint: true
    })).toMatchObject({
      action: "require_approval",
      matchedRuleId: "block-tainted-sink"
    });
  });

  it("blocks sensitive egress and redacts PII with the shipped egress preset", async () => {
    const egress = await loadPolicyFile(join(process.cwd(), "policies", "egress.yaml"));

    expect(evaluatePolicy(egress, {
      direction: "request",
      method: "tools/call",
      tool_class: "sink",
      capabilities: ["sends_message"],
      sensitive_taint: true
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-secret-egress"
    });

    expect(evaluatePolicy(egress, {
      direction: "request",
      method: "tools/call",
      capabilities: ["sends_message"],
      pii_detected: true
    })).toMatchObject({
      action: "redact_secrets",
      matchedRuleId: "redact-pii-egress"
    });

    expect(evaluatePolicy(egress, {
      direction: "request",
      method: "tools/call",
      tool_class: "sink",
      capabilities: ["network_egress"],
      taint: true,
      destination_allowed: true,
      destination_allowlist_configured: true
    })).toMatchObject({
      action: "allow",
      matchedRuleId: "allow-tainted-allowed-egress-destination"
    });
  });
});
