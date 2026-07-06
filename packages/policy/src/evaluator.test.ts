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
    const shippedStrict = await loadPolicyFile(join(process.cwd(), "policies", "strict.yaml"));

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

  it("applies the shipped coding-agent preset to common agent tool risks", async () => {
    const codingAgent = await loadPolicyFile(join(process.cwd(), "policies", "coding-agent.yaml"));

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      tool_class: "source",
      taint: false,
      sensitive_taint: false
    })).toMatchObject({
      action: "allow"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      tool_class: "sink",
      capabilities: ["file_write", "writes_local"],
      taint: false,
      sensitive_taint: false
    })).toMatchObject({
      action: "allow"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      argument_roles: ["shell_command"]
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-shell-command-role"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      argument_text: "{\"path\":\"/workspace/.ssh/id_rsa\"}",
      argument_roles: ["file_path"]
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-credential-path-access"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      capabilities: ["sends_message"],
      secret_detected: true
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-secret-detected-coding-agent"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      capabilities: ["file_write", "writes_local"],
      sensitive_taint: true
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-sensitive-taint-coding-agent"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      capabilities: ["network_egress"],
      tainted_argument_roles: ["url"]
    })).toMatchObject({
      action: "block",
      matchedRuleId: "block-tainted-network-or-message-egress"
    });

    expect(evaluatePolicy(codingAgent, {
      direction: "request",
      method: "tools/call",
      tool_class: "sink",
      capabilities: ["file_write", "writes_local"],
      taint: true
    })).toMatchObject({
      action: "require_approval",
      matchedRuleId: "require-approval-tainted-file-write"
    });
  });
});
