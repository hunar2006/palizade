import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "./evaluator.js";
import { parsePolicy } from "./loader.js";
import type { PolicyDocument, ToolCapability } from "./types.js";

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

  it("blocks sink classes in the research read-only preset", () => {
    const researchPolicy = parsePolicy(
      readFileSync(
        new URL("../../../policies/research-read-only.yaml", import.meta.url),
        "utf8"
      )
    );
    const blockedCapabilities: ToolCapability[] = [
      "writes_local",
      "writes_remote",
      "deletes_data",
      "executes_code",
      "sends_message",
      "accesses_credentials"
    ];

    expect(
      evaluatePolicy(researchPolicy, {
        direction: "request",
        method: "tools/call",
        tool_class: "sink"
      }).action
    ).toBe("block");

    expect(
      evaluatePolicy(researchPolicy, {
        direction: "request",
        method: "tools/call",
        tool_class: "unknown"
      }).action
    ).toBe("block");

    for (const capability of blockedCapabilities) {
      expect(
        evaluatePolicy(researchPolicy, {
          direction: "request",
          method: "tools/call",
          tool_class: "pure",
          capabilities: [capability]
        }).action
      ).toBe("block");
    }

    expect(
      evaluatePolicy(researchPolicy, {
        direction: "request",
        method: "tools/call",
        tool_class: "source",
        capabilities: ["reads_untrusted_content"]
      }).action
    ).toBe("allow");
  });
});
