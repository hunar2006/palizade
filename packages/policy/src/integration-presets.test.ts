import { expect, it } from "vitest";
import { evaluatePolicy } from "./evaluator.js";
import { loadPolicyFile } from "./loader.js";
import type { PolicyContext } from "./types.js";

const sink: PolicyContext = { direction: "request", method: "tools/call", tool_class: "sink", capabilities: ["network_egress", "sends_message"], destination_allowed: true, destination_allowlist_configured: true };

it.each(["default", "interactive", "strict", "egress", "coding-agent"])("%s blocks a tainted query before generic approval/redaction", async (preset) => {
  const policy = await loadPolicyFile(`policies/${preset}.yaml`);
  expect(evaluatePolicy(policy, { ...sink, taint: true, pii_detected: true, tainted_argument_roles: ["http_query"] }).action).toBe("block");
});
it("blocks strict suspicious output before sanitization and split egress before PII redaction", async () => {
  expect(evaluatePolicy(await loadPolicyFile("policies/strict.yaml"), { direction: "response", method: "tools/call", detector_score: 0.85 }).action).toBe("block");
  expect(evaluatePolicy(await loadPolicyFile("policies/egress.yaml"), { ...sink, split_match: true, pii_detected: true }).matchedRuleId).toBe("block-split-match");
});
it("egress exceptions cannot bypass critical-path or quarantine approval", async () => {
  const policy = await loadPolicyFile("policies/egress.yaml");
  const fileSink = { ...sink, capabilities: ["writes_local", "network_egress"] } as PolicyContext;
  expect(evaluatePolicy(policy, { ...fileSink, pii_detected: true, critical_path: true }).matchedRuleId).toBe("approve-critical-path");
  expect(evaluatePolicy(policy, { ...sink, pii_detected: true, session_quarantined: true }).matchedRuleId).toBe("approve-quarantined-sink");
  expect(evaluatePolicy(policy, { ...sink, pii_detected: true }).action).toBe("redact_secrets");
  expect(evaluatePolicy(policy, { ...sink, taint: true }).action).toBe("allow");
});
it("research gates permitted output during quarantine and passes normal output", async () => {
  const policy = await loadPolicyFile("policies/research-readonly.yaml");
  const output = { ...sink, capabilities: ["writes_local"], output_path_allowed: true } as PolicyContext;
  expect(evaluatePolicy(policy, { ...output, session_quarantined: true }).action).toBe("require_approval");
  expect(evaluatePolicy(policy, output).action).toBe("allow");
});
