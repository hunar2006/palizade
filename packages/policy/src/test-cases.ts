import { z } from "zod";
import { parseYamlWithSchema } from "./errors.js";
import { evaluatePolicy } from "./evaluator.js";
import { actionSchema, capabilitySchema, directionSchema, lockStatusSchema, toolClassSchema, trustSchema } from "./schema.js";
import type { PolicyContext, PolicyDocument } from "./types.js";

// Strict, so a misspelled field fails the test file instead of silently matching nothing.
const contextSchema = z.object({
  direction: directionSchema,
  method: z.string().optional(),
  server: z.string().optional(),
  tool: z.string().optional(),
  tool_class: toolClassSchema.optional(),
  capabilities: z.array(capabilitySchema).optional(),
  trust: trustSchema.optional(),
  taint: z.boolean().optional(),
  sensitive_taint: z.boolean().optional(),
  temporal_taint: z.boolean().optional(),
  secret_detected: z.boolean().optional(),
  pii_detected: z.boolean().optional(),
  destination_allowed: z.boolean().optional(),
  tainted_destination: z.boolean().optional(),
  user_stated_destination: z.boolean().optional(),
  lookalike_destination: z.boolean().optional(),
  new_destination: z.boolean().optional(),
  split_match: z.boolean().optional(),
  rule_of_two: z.boolean().optional(),
  session_untrusted: z.boolean().optional(),
  rate_limited: z.boolean().optional(),
  loop_detected: z.boolean().optional(),
  destination_session_trusted: z.boolean().optional(),
  destination_allowlist_configured: z.boolean().optional(),
  detector_score: z.number().min(0).max(1).optional(),
  labels: z.array(z.string()).optional(),
  lock_status: lockStatusSchema.optional(),
  argument_text: z.string().optional(),
  argument_paths: z.array(z.string()).optional(),
  critical_path: z.boolean().optional(),
  git_push_unapproved: z.boolean().optional(),
  output_path_allowed: z.boolean().optional(),
  argument_roles: z.array(z.string()).optional(),
  tainted_argument_roles: z.array(z.string()).optional(),
  session_quarantined: z.boolean().optional(),
  tool_shadowing_detected: z.boolean().optional(),
  name_collision_detected: z.boolean().optional(),
  hidden_unicode_detected: z.boolean().optional()
}).strict();

const expectSchema = z.union([
  actionSchema,
  z.object({ action: actionSchema.optional(), rule: z.string().optional(), not_rule: z.string().optional() }).strict()
]);

export const policyTestFileSchema = z.object({
  policy: z.string().optional(),
  cases: z.array(z.object({
    name: z.string().min(1),
    context: contextSchema,
    expect: expectSchema
  }).strict()).min(1)
}).strict();

export type PolicyTestFile = z.infer<typeof policyTestFileSchema>;

export interface PolicyTestResult {
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
}

export function parsePolicyTests(raw: string, file: string): PolicyTestFile {
  return parseYamlWithSchema(policyTestFileSchema, raw, file);
}

export function runPolicyTests(policy: PolicyDocument, tests: PolicyTestFile): PolicyTestResult[] {
  return tests.cases.map((testCase) => {
    const decision = evaluatePolicy(policy, testCase.context as PolicyContext);
    const want = typeof testCase.expect === "string" ? { action: testCase.expect } : testCase.expect;
    const passed = (want.action === undefined || decision.action === want.action)
      && (want.rule === undefined || decision.matchedRuleId === want.rule)
      && (want.not_rule === undefined || decision.matchedRuleId !== want.not_rule);
    const expected = [want.action, want.rule ? `rule ${want.rule}` : "", want.not_rule ? `not rule ${want.not_rule}` : ""].filter(Boolean).join(", ");
    return { name: testCase.name, passed, expected, actual: `${decision.action}${decision.matchedRuleId ? `, rule ${decision.matchedRuleId}` : ", default"}` };
  });
}
