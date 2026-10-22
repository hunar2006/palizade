export type PolicyAction = "allow" | "block" | "sanitize" | "redact_spans" | "redact_secrets" | "require_approval" | "log_only";

export type Direction = "request" | "response";
export type TrustLevel = "trusted" | "semi" | "untrusted";
export type ToolClass = "source" | "sink" | "pure" | "unknown";
export type LockStatus = "approved" | "new" | "changed" | "missing" | "unknown";
export type ToolCapability =
  | "reads_untrusted_content"
  | "reads_sensitive_data"
  | "network_egress"
  | "file_write"
  | "writes_local"
  | "writes_remote"
  | "persists_memory"
  | "deletes_data"
  | "executes_code"
  | "sends_message"
  | "accesses_credentials"
  | "invokes_model"
  | "user_interaction";

export interface PolicyRule {
  id: string;
  name?: string | undefined;
  when?: PolicyCondition | undefined;
  action: PolicyAction;
  reason?: string | undefined;
}

export interface PolicyCondition {
  direction?: Direction | Direction[] | undefined;
  method?: string | string[] | undefined;
  server?: string | string[] | undefined;
  tool?: string | string[] | undefined;
  tool_class?: ToolClass | ToolClass[] | undefined;
  capabilities_any?: ToolCapability[] | undefined;
  capabilities_all?: ToolCapability[] | undefined;
  trust?: TrustLevel | TrustLevel[] | undefined;
  taint?: boolean | undefined;
  sensitive_taint?: boolean | undefined;
  temporal_taint?: boolean | undefined;
  secret_detected?: boolean | undefined;
  pii_detected?: boolean | undefined;
  destination_allowed?: boolean | undefined;
  tainted_destination?: boolean | undefined;
  user_stated_destination?: boolean | undefined;
  copied_link_only?: boolean | undefined;
  lookalike_destination?: boolean | undefined;
  new_destination?: boolean | undefined;
  split_match?: boolean | undefined;
  rule_of_two?: boolean | undefined;
  session_untrusted?: boolean | undefined;
  rate_limited?: boolean | undefined;
  loop_detected?: boolean | undefined;
  destination_session_trusted?: boolean | undefined;
  destination_allowlist_configured?: boolean | undefined;
  detector_score_gte?: number | undefined;
  detector_score_lt?: number | undefined;
  labels_any?: string[] | undefined;
  lock_status?: LockStatus | LockStatus[] | undefined;
  argument_regex?: string | undefined;
  argument_path_glob?: string[] | undefined;
  critical_path?: boolean | undefined;
  git_push_unapproved?: boolean | undefined;
  output_path_allowed?: boolean | undefined;
  argument_role_any?: string[] | undefined;
  tainted_argument_role_any?: string[] | undefined;
  session_quarantined?: boolean | undefined;
  tool_shadowing_detected?: boolean | undefined;
  name_collision_detected?: boolean | undefined;
  hidden_unicode_detected?: boolean | undefined;
}

export interface PolicyDocument {
  version: 1;
  defaults: {
    action: PolicyAction;
    on_error: PolicyAction;
  };
  rules: PolicyRule[];
}

export interface PolicyContext {
  direction: Direction;
  method?: string | undefined;
  server?: string | undefined;
  tool?: string | undefined;
  tool_class?: ToolClass | undefined;
  capabilities?: ToolCapability[] | undefined;
  trust?: TrustLevel | undefined;
  taint?: boolean | undefined;
  sensitive_taint?: boolean | undefined;
  temporal_taint?: boolean | undefined;
  secret_detected?: boolean | undefined;
  pii_detected?: boolean | undefined;
  destination_allowed?: boolean | undefined;
  tainted_destination?: boolean | undefined;
  user_stated_destination?: boolean | undefined;
  copied_link_only?: boolean | undefined;
  lookalike_destination?: boolean | undefined;
  new_destination?: boolean | undefined;
  split_match?: boolean | undefined;
  rule_of_two?: boolean | undefined;
  session_untrusted?: boolean | undefined;
  rate_limited?: boolean | undefined;
  loop_detected?: boolean | undefined;
  destination_session_trusted?: boolean | undefined;
  destination_allowlist_configured?: boolean | undefined;
  detector_score?: number | undefined;
  labels?: string[] | undefined;
  lock_status?: LockStatus | undefined;
  argument_text?: string | undefined;
  argument_paths?: string[] | undefined;
  critical_path?: boolean | undefined;
  git_push_unapproved?: boolean | undefined;
  output_path_allowed?: boolean | undefined;
  argument_roles?: string[] | undefined;
  tainted_argument_roles?: string[] | undefined;
  session_quarantined?: boolean | undefined;
  tool_shadowing_detected?: boolean | undefined;
  name_collision_detected?: boolean | undefined;
  hidden_unicode_detected?: boolean | undefined;
}

export interface PolicyDecision {
  action: PolicyAction;
  matchedRuleId?: string | undefined;
  matchedRuleName?: string | undefined;
  reason: string;
  failClosed?: boolean | undefined;
}
