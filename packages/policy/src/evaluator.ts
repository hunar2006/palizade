import type { PolicyCondition, PolicyContext, PolicyDecision, PolicyDocument, PolicyRule } from "./types.js";
import { matchesPathGlob } from "./paths.js";

export function evaluatePolicy(policy: PolicyDocument, ctx: PolicyContext): PolicyDecision {
  try {
    for (const rule of policy.rules) {
      if (matchesRule(rule, ctx)) {
        return {
          action: rule.action,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          reason: rule.reason ?? `matched policy rule ${rule.id}`
        };
      }
    }
    return {
      action: policy.defaults.action,
      reason: "policy default"
    };
  } catch (error) {
    return {
      action: policy.defaults.on_error,
      reason: `policy evaluation error: ${error instanceof Error ? error.message : String(error)}`,
      failClosed: policy.defaults.on_error === "block"
    };
  }
}

export function matchesRule(rule: PolicyRule, ctx: PolicyContext): boolean {
  if (!rule.when) {
    return true;
  }
  return matchesCondition(rule.when, ctx);
}

function matchesCondition(condition: PolicyCondition, ctx: PolicyContext): boolean {
  if (!matchesMaybeArray(condition.direction, ctx.direction)) return false;
  if (!matchesMaybeArray(condition.method, ctx.method)) return false;
  if (!matchesMaybeArray(condition.server, ctx.server)) return false;
  if (!matchesMaybeArray(condition.tool, ctx.tool)) return false;
  if (!matchesMaybeArray(condition.tool_class, ctx.tool_class)) return false;
  if (condition.capabilities_any && !condition.capabilities_any.some((capability) => ctx.capabilities?.includes(capability))) return false;
  if (condition.capabilities_all && !condition.capabilities_all.every((capability) => ctx.capabilities?.includes(capability))) return false;
  if (!matchesMaybeArray(condition.trust, ctx.trust)) return false;
  if (!matchesMaybeArray(condition.lock_status, ctx.lock_status)) return false;
  if (condition.taint !== undefined && Boolean(ctx.taint) !== condition.taint) return false;
  if (condition.sensitive_taint !== undefined && Boolean(ctx.sensitive_taint) !== condition.sensitive_taint) return false;
  if (condition.temporal_taint !== undefined && Boolean(ctx.temporal_taint) !== condition.temporal_taint) return false;
  if (condition.secret_detected !== undefined && Boolean(ctx.secret_detected) !== condition.secret_detected) return false;
  if (condition.pii_detected !== undefined && Boolean(ctx.pii_detected) !== condition.pii_detected) return false;
  if (condition.destination_allowed !== undefined && Boolean(ctx.destination_allowed) !== condition.destination_allowed) return false;
  if (condition.tainted_destination !== undefined && Boolean(ctx.tainted_destination) !== condition.tainted_destination) return false;
  if (condition.user_stated_destination !== undefined && Boolean(ctx.user_stated_destination) !== condition.user_stated_destination) return false;
  if (condition.copied_link_only !== undefined && Boolean(ctx.copied_link_only) !== condition.copied_link_only) return false;
  if (condition.tool_metadata_taint !== undefined && Boolean(ctx.tool_metadata_taint) !== condition.tool_metadata_taint) return false;
  if (condition.lookalike_destination !== undefined && Boolean(ctx.lookalike_destination) !== condition.lookalike_destination) return false;
  if (condition.new_destination !== undefined && Boolean(ctx.new_destination) !== condition.new_destination) return false;
  if (condition.split_match !== undefined && Boolean(ctx.split_match) !== condition.split_match) return false;
  if (condition.rule_of_two !== undefined && Boolean(ctx.rule_of_two) !== condition.rule_of_two) return false;
  if (condition.session_untrusted !== undefined && Boolean(ctx.session_untrusted) !== condition.session_untrusted) return false;
  if (condition.rate_limited !== undefined && Boolean(ctx.rate_limited) !== condition.rate_limited) return false;
  if (condition.loop_detected !== undefined && Boolean(ctx.loop_detected) !== condition.loop_detected) return false;
  if (condition.critical_path !== undefined && Boolean(ctx.critical_path) !== condition.critical_path) return false;
  if (condition.git_push_unapproved !== undefined && Boolean(ctx.git_push_unapproved) !== condition.git_push_unapproved) return false;
  if (condition.output_path_allowed !== undefined && Boolean(ctx.output_path_allowed) !== condition.output_path_allowed) return false;
  if (condition.argument_path_glob && !condition.argument_path_glob.some((pattern) => ctx.argument_paths?.some((path) => matchesPathGlob(path, pattern)))) return false;
  if (condition.destination_session_trusted !== undefined && Boolean(ctx.destination_session_trusted) !== condition.destination_session_trusted) return false;
  if (condition.destination_allowlist_configured !== undefined && Boolean(ctx.destination_allowlist_configured) !== condition.destination_allowlist_configured) return false;
  if (condition.session_quarantined !== undefined && Boolean(ctx.session_quarantined) !== condition.session_quarantined) return false;
  if (condition.tool_shadowing_detected !== undefined && Boolean(ctx.tool_shadowing_detected) !== condition.tool_shadowing_detected) return false;
  if (condition.name_collision_detected !== undefined && Boolean(ctx.name_collision_detected) !== condition.name_collision_detected) return false;
  if (condition.hidden_unicode_detected !== undefined && Boolean(ctx.hidden_unicode_detected) !== condition.hidden_unicode_detected) return false;
  if (condition.detector_score_gte !== undefined && (ctx.detector_score ?? 0) < condition.detector_score_gte) return false;
  if (condition.detector_score_lt !== undefined && (ctx.detector_score ?? 0) >= condition.detector_score_lt) return false;
  if (condition.labels_any && !condition.labels_any.some((label) => ctx.labels?.includes(label))) return false;
  if (condition.argument_regex) {
    const regex = new RegExp(condition.argument_regex, "iu");
    if (!regex.test(ctx.argument_text ?? "")) return false;
  }
  if (condition.argument_role_any && !condition.argument_role_any.some((role) => ctx.argument_roles?.includes(role))) return false;
  if (condition.tainted_argument_role_any && !condition.tainted_argument_role_any.some((role) => ctx.tainted_argument_roles?.includes(role))) return false;
  return true;
}

function matchesMaybeArray<T extends string>(expected: T | T[] | undefined, actual: T | undefined): boolean {
  if (expected === undefined) {
    return true;
  }
  if (actual === undefined) {
    return false;
  }
  return Array.isArray(expected) ? expected.includes(actual) : expected === actual;
}
