import type { PolicyCondition, PolicyContext, PolicyDecision, PolicyDocument, PolicyRule } from "./types.js";

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
  if (condition.temporal_taint !== undefined && Boolean(ctx.temporal_taint) !== condition.temporal_taint) return false;
  if (condition.session_quarantined !== undefined && Boolean(ctx.session_quarantined) !== condition.session_quarantined) return false;
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
