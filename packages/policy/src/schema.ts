import { z } from "zod";

const actionSchema = z.enum(["allow", "block", "sanitize", "redact_spans", "redact_secrets", "require_approval", "log_only"]);
const directionSchema = z.enum(["request", "response"]);
const trustSchema = z.enum(["trusted", "semi", "untrusted"]);
const toolClassSchema = z.enum(["source", "sink", "pure", "unknown"]);
const lockStatusSchema = z.enum(["approved", "new", "changed", "missing", "unknown"]);
const capabilitySchema = z.enum([
  "reads_untrusted_content",
  "reads_sensitive_data",
  "network_egress",
  "file_write",
  "writes_local",
  "writes_remote",
  "deletes_data",
  "executes_code",
  "sends_message",
  "accesses_credentials",
  "invokes_model",
  "user_interaction"
]);

function singleOrArray<T extends z.ZodTypeAny>(schema: T): z.ZodUnion<[T, z.ZodArray<T>]> {
  return z.union([schema, z.array(schema)]);
}

export const policyConditionSchema = z.object({
  direction: singleOrArray(directionSchema).optional(),
  method: singleOrArray(z.string()).optional(),
  server: singleOrArray(z.string()).optional(),
  tool: singleOrArray(z.string()).optional(),
  tool_class: singleOrArray(toolClassSchema).optional(),
  capabilities_any: z.array(capabilitySchema).optional(),
  capabilities_all: z.array(capabilitySchema).optional(),
  trust: singleOrArray(trustSchema).optional(),
  taint: z.boolean().optional(),
  sensitive_taint: z.boolean().optional(),
  temporal_taint: z.boolean().optional(),
  secret_detected: z.boolean().optional(),
  pii_detected: z.boolean().optional(),
  destination_allowed: z.boolean().optional(),
  destination_allowlist_configured: z.boolean().optional(),
  detector_score_gte: z.number().min(0).max(1).optional(),
  detector_score_lt: z.number().min(0).max(1).optional(),
  labels_any: z.array(z.string()).optional(),
  lock_status: singleOrArray(lockStatusSchema).optional(),
  argument_regex: z.string().optional(),
  argument_role_any: z.array(z.string()).optional(),
  tainted_argument_role_any: z.array(z.string()).optional(),
  session_quarantined: z.boolean().optional()
}).strict();

export const policyRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().optional(),
  when: policyConditionSchema.optional(),
  action: actionSchema,
  reason: z.string().optional()
}).strict();

export const policyDocumentSchema = z.object({
  version: z.literal(1),
  defaults: z.object({
    action: actionSchema.default("allow"),
    on_error: actionSchema.default("block")
  }).default({ action: "allow", on_error: "block" }),
  rules: z.array(policyRuleSchema).default([])
}).strict();
