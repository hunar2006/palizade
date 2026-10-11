import { createLineLocator, parseYamlWithSchema, SchemaValidationError } from "./errors.js";
import { policyDocumentSchema } from "./schema.js";
import type { PolicyCondition, PolicyDocument, PolicyRule } from "./types.js";

export type PolicyCheckKind = "schema" | "unknown_key" | "unreachable" | "impossible" | "unknown_reference" | "duplicate_id";

export interface PolicyFinding {
  level: "error" | "warning";
  check: PolicyCheckKind;
  path: string;
  line?: number | undefined;
  ruleId?: string | undefined;
  message: string;
  hint: string;
}

export interface PolicyCheckContext {
  /** Server names from palizade.yaml. Server references are checked only when this is set. */
  servers?: string[] | undefined;
  /** Known tool names per server (palizade.lock plus palizade.yaml overrides). Tool references are checked only for servers with at least one known tool. */
  toolsByServer?: Record<string, string[]> | undefined;
}

export interface PolicyCheckResult {
  policy?: PolicyDocument | undefined;
  findings: PolicyFinding[];
}

const LIST_CONDITIONS = ["direction", "method", "server", "tool", "tool_class", "trust", "lock_status", "capabilities_any", "labels_any", "argument_path_glob", "argument_role_any", "tainted_argument_role_any"] as const;

export function checkPolicy(raw: string, file: string, context: PolicyCheckContext = {}): PolicyCheckResult {
  let policy: PolicyDocument;
  try {
    policy = parseYamlWithSchema(policyDocumentSchema, raw, file);
  } catch (error) {
    if (!(error instanceof SchemaValidationError)) throw error;
    return {
      findings: error.problems.map((problem) => ({
        level: "error",
        check: problem.message.startsWith("Unknown key") ? "unknown_key" : "schema",
        path: problem.path,
        line: problem.line,
        message: problem.message,
        hint: problem.hint
      }))
    };
  }

  const lineOf = createLineLocator(raw);
  const findings: PolicyFinding[] = [];
  const add = (finding: Omit<PolicyFinding, "line">, path: Array<string | number>): void => {
    findings.push({ ...finding, line: lineOf(path) });
  };
  const seenIds = new Map<string, number>();
  let catchAll: { id: string; index: number } | undefined;

  policy.rules.forEach((rule, index) => {
    const rulePath = `rules.${index}`;
    const previous = seenIds.get(rule.id);
    if (previous !== undefined) {
      add({ level: "warning", check: "duplicate_id", path: `${rulePath}.id`, ruleId: rule.id, message: `Rule id '${rule.id}' is already used by rules.${previous}.`, hint: "Give every rule a unique id so audit entries point at one rule." }, ["rules", index, "id"]);
    } else {
      seenIds.set(rule.id, index);
    }

    if (catchAll) {
      add({ level: "warning", check: "unreachable", path: rulePath, ruleId: rule.id, message: `Rule '${rule.id}' can never match: rule '${catchAll.id}' (rules.${catchAll.index}) matches everything first.`, hint: `Move '${rule.id}' above '${catchAll.id}', or delete it.` }, ["rules", index]);
    }

    for (const problem of impossibleConditions(rule)) {
      add({ level: problem.level, check: "impossible", path: `${rulePath}.when.${problem.key}`, ruleId: rule.id, message: problem.message, hint: problem.hint }, ["rules", index, "when", problem.key]);
    }

    for (const reference of unknownReferences(rule, context)) {
      add({ level: "warning", check: "unknown_reference", path: `${rulePath}.when.${reference.key}`, ruleId: rule.id, message: reference.message, hint: reference.hint }, ["rules", index, "when", reference.key]);
    }

    if (!catchAll && isCatchAll(rule)) catchAll = { id: rule.id, index };
  });

  return { policy, findings };
}

export function isCatchAll(rule: PolicyRule): boolean {
  const when = rule.when;
  if (!when) return true;
  const keys = Object.keys(when).filter((key) => when[key as keyof PolicyCondition] !== undefined);
  if (keys.length === 0) return true;
  // `direction: [request, response]` alone also matches every evaluated message.
  return keys.length === 1 && keys[0] === "direction" && Array.isArray(when.direction) && when.direction.includes("request") && when.direction.includes("response");
}

function impossibleConditions(rule: PolicyRule): Array<{ key: string; level: "error" | "warning"; message: string; hint: string }> {
  const when = rule.when;
  if (!when) return [];
  const problems: Array<{ key: string; level: "error" | "warning"; message: string; hint: string }> = [];
  for (const key of LIST_CONDITIONS) {
    const value = when[key];
    if (Array.isArray(value) && value.length === 0) {
      problems.push({ key, level: "warning", message: `'${key}: []' never matches, so rule '${rule.id}' never fires.`, hint: `List at least one value, or remove '${key}'.` });
    }
  }
  if (when.detector_score_gte !== undefined && when.detector_score_lt !== undefined && when.detector_score_gte >= when.detector_score_lt) {
    problems.push({ key: "detector_score_lt", level: "warning", message: `detector_score_gte ${when.detector_score_gte} and detector_score_lt ${when.detector_score_lt} cannot both hold.`, hint: "Make detector_score_gte smaller than detector_score_lt." });
  } else if (when.detector_score_lt === 0) {
    problems.push({ key: "detector_score_lt", level: "warning", message: "detector_score_lt: 0 never matches; scores are never below 0.", hint: "Use a positive threshold." });
  }
  if (when.argument_regex !== undefined) {
    try {
      new RegExp(when.argument_regex, "iu");
    } catch {
      problems.push({ key: "argument_regex", level: "error", message: "argument_regex is not a valid regular expression; every evaluation of this rule fails and falls back to defaults.on_error.", hint: "Fix the pattern (it is compiled with the i and u flags)." });
    }
  }
  return problems;
}

function unknownReferences(rule: PolicyRule, context: PolicyCheckContext): Array<{ key: string; message: string; hint: string }> {
  const when = rule.when;
  if (!when) return [];
  const references: Array<{ key: string; message: string; hint: string }> = [];
  const servers = asList(when.server);
  if (context.servers && servers.length > 0) {
    const unknown = servers.filter((server) => !context.servers!.includes(server));
    if (unknown.length > 0) {
      references.push({ key: "server", message: `Server${unknown.length > 1 ? "s" : ""} ${unknown.map((name) => `'${name}'`).join(", ")} ${unknown.length > 1 ? "are" : "is"} not in palizade.yaml.`, hint: context.servers.length > 0 ? `Configured servers: ${context.servers.join(", ")}.` : "Add the server to palizade.yaml or remove the condition." });
    }
  }
  const tools = asList(when.tool);
  if (context.toolsByServer && tools.length > 0) {
    const scope = servers.length > 0 ? servers : Object.keys(context.toolsByServer);
    const known = new Set(scope.flatMap((server) => context.toolsByServer?.[server] ?? []));
    if (known.size > 0) {
      const unknown = tools.filter((tool) => !known.has(tool));
      if (unknown.length > 0) {
        references.push({ key: "tool", message: `Tool${unknown.length > 1 ? "s" : ""} ${unknown.map((name) => `'${name}'`).join(", ")} ${unknown.length > 1 ? "are" : "is"} not exposed by ${servers.length > 0 ? servers.join(", ") : "any locked server"}.`, hint: "Check the spelling against 'palizade lock diff <server>', or run 'palizade lock approve' if the tool is new." });
      }
    }
  }
  return references;
}

function asList<T>(value: T | T[] | undefined): T[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}
