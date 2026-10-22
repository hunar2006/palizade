import type { ToolCapability, ToolClass } from "@palizade/policy";
import type { McpTool } from "./mcp.js";
import type { ArgumentRole } from "./arguments.js";
import type { ServerConfig } from "./config.js";
import { catalogMatch } from "./tool-catalog.js";

const SINK_RE = /\b(send|post|put|patch|delete|write|save|exec|shell|run|spawn|email|sms|publish|commit|push|upload|http|fetch|request|webhook)\b/iu;
const SOURCE_RE = /\b(read|get|fetch|search|browse|list|download|crawl|open|load|query|receive|inbox|issue|pull|web|url|file)\b/iu;
const CAPABILITY_RULES: Array<[RegExp, ToolCapability[]]> = [
  [/\b(create entities|add observations|create relations|add memory|store memory|remember|save note|upsert|(?:write|add|insert|store|save).{0,24}(?:vector|memory)|(?:vector|memory).{0,24}(?:write|add|insert|store|save))\b/iu, ["persists_memory", "writes_remote"]],
  [/\b(fetch|http|post|put|patch|request|webhook|url|browser|crawl)\b/iu, ["network_egress", "reads_untrusted_content"]],
  [/\b(email|mail|send|sms|slack|discord|message|publish)\b/iu, ["sends_message", "writes_remote", "network_egress"]],
  [/\b(write|save|edit|create|move|append)\b/iu, ["file_write", "writes_local"]],
  [/\b(delete|remove|rm|destroy)\b/iu, ["deletes_data"]],
  // Verbs that change shared state somewhere else: membership, settings, sharing, scheduling.
  [/\b(add|invite|update|set|assign|grant|share|rename|archive|reply|forward|schedule|cancel)\b/iu, ["writes_remote"]],
  // shortcut: verb match only, so read tools like get_transfer_history also become sinks (over-block, fails closed).
  [/\b(buy|sell|trade|transfer|withdraw|deposit|pay|payment|purchase|refund|place order)\b/iu, ["writes_remote"]],
  [/\b(exec|shell|run|spawn|command|script|terminal)\b/iu, ["executes_code"]],
  [/\b(secret|credential|token|key|env|password)\b/iu, ["accesses_credentials", "reads_sensitive_data"]],
  [/\b(model|sample|llm|completion|chat)\b/iu, ["invokes_model"]],
  [/\b(read|get|list|search|browse|open|download|load|query|inbox|issue|pull|file)\b/iu, ["reads_untrusted_content"]]
];

export interface ToolClassification {
  toolClass: ToolClass;
  capabilities: ToolCapability[];
  /** Why the class was chosen, for audit, doctor and `palizade tools`. */
  reasons: string[];
  /** Argument roles from the catalog; config argumentRoles still take precedence. */
  argumentRoles?: Record<string, ArgumentRole>;
}

// Input property names that only make sense for actions with side effects. Schemas from
// untrusted servers can only add these capabilities, never remove one.
const SCHEMA_SIGNALS: Array<[RegExp, ToolCapability[], string]> = [
  [/^(to|cc|bcc|recipients?|recipient_email|email_to|phone_number|webhook_url|webhook)$/iu, ["sends_message", "network_egress", "writes_remote"], "recipient"],
  [/^(command|cmd|shell_command|script|code|javascript|python)$/iu, ["executes_code"], "code"],
  [/^(amount|iban|account_number|routing_number|recipient_account)$/iu, ["writes_remote"], "payment"],
  [/^(url|uri|endpoint)$/iu, ["network_egress"], "url"]
];
const WRITE_BODY = /^(content|contents|new_content|file_content|data|text|body|patch|diff)$/iu;
const PATH_FIELD = /^(path|file|file_path|filepath|filename|target|destination)$/iu;

export function classifyTool(toolName: string, server: ServerConfig, tool?: McpTool): ToolClass {
  return classifyToolDetailed(toolName, server, tool).toolClass;
}

export function classifyToolDetailed(toolName: string, server: ServerConfig, tool?: McpTool): ToolClassification {
  const configured = server.toolClasses[toolName];
  const capabilities = new Set<ToolCapability>(server.toolCapabilities[toolName] ?? []);
  const reasons: string[] = configured ? [`config:${configured}`] : [];
  const trusted = server.trust === "trusted";
  const annotationCaps = capabilitiesFromAnnotations(tool?.annotations);
  const raisingAnnotation = tool?.annotations?.destructiveHint === true || tool?.annotations?.openWorldHint === true;
  for (const capability of annotationCaps) {
    if (!trusted && capability === "reads_untrusted_content" && tool?.annotations?.openWorldHint !== true) continue;
    capabilities.add(capability);
  }

  const catalog = catalogMatch(toolName, server);
  if (catalog) {
    catalog.rule.capabilities.forEach((capability) => capabilities.add(capability));
    reasons.push(`catalog:${catalog.entry.id}`);
    // Annotations may still raise a catalog class to sink, never lower it.
    const toolClass = configured ?? (raisingAnnotation ? "sink" : catalog.rule.toolClass);
    if (!configured && raisingAnnotation && catalog.rule.toolClass !== "sink") reasons.push("annotation:raised");
    return { toolClass, capabilities: [...capabilities], reasons, ...(catalog.rule.roles ? { argumentRoles: catalog.rule.roles } : {}) };
  }

  const annotationClass = trusted || raisingAnnotation ? classFromAnnotations(tool?.annotations) : undefined;
  if (annotationClass) reasons.push(`annotation:${annotationClass}`);

  // Split snake, kebab and camelCase so GmailSendEmail reads as "Gmail Send Email" for the \b rules.
  const words = (text: string) => text.replace(/([a-z0-9])([A-Z])/gu, "$1 $2").replace(/[_-]+/gu, " ");
  const name = words(`${toolName} ${trusted ? tool?.title ?? "" : ""}`);
  // The name is what the user approves; free text from an untrusted server is not evidence of safety.
  const description = words(`${trusted ? "" : tool?.title ?? ""} ${tool?.description ?? ""}`);
  let sourceEvidence = false;
  for (const [regex, matched] of CAPABILITY_RULES) {
    if (regex.test(name)) {
      matched.forEach((capability) => capabilities.add(capability));
      if (matched.includes("reads_untrusted_content")) sourceEvidence = true;
      reasons.push(`name:${matched[0]}`);
    } else if (regex.test(description)) {
      const added = trusted ? matched : matched.filter((capability) => capability !== "reads_untrusted_content");
      added.forEach((capability) => capabilities.add(capability));
      if (trusted && matched.includes("reads_untrusted_content")) sourceEvidence = true;
      if (added.length > 0) reasons.push(`description:${added[0]}`);
    }
  }
  for (const [signal, matched] of schemaSignals(tool?.inputSchema)) {
    matched.forEach((capability) => capabilities.add(capability));
    reasons.push(`schema:${signal}`);
  }
  if (annotationCaps.includes("reads_untrusted_content") && (trusted || tool?.annotations?.openWorldHint === true)) sourceEvidence = true;

  const derived = deriveClass(words(toolName), capabilities, sourceEvidence);
  if (!configured && !annotationClass) reasons.push(`derived:${derived}`);
  return {
    toolClass: configured ?? annotationClass ?? derived,
    capabilities: [...capabilities],
    reasons: [...new Set(reasons)]
  };
}

/** Capabilities implied by input property names, at the top level and one level down. */
export function schemaSignals(schema: unknown): Array<[string, ToolCapability[]]> {
  const names = propertyNames(schema, 2);
  const found: Array<[string, ToolCapability[]]> = [];
  for (const [regex, capabilities, label] of SCHEMA_SIGNALS) {
    if (names.some((name) => regex.test(name))) found.push([label, capabilities]);
  }
  if (names.some((name) => PATH_FIELD.test(name)) && names.some((name) => WRITE_BODY.test(name))) found.push(["path+content", ["file_write", "writes_local"]]);
  return found;
}

function propertyNames(schema: unknown, depth: number): string[] {
  if (!schema || typeof schema !== "object" || depth === 0) return [];
  const node = schema as { properties?: unknown; items?: unknown };
  const names: string[] = [];
  if (node.properties && typeof node.properties === "object") {
    for (const [key, child] of Object.entries(node.properties as Record<string, unknown>).slice(0, 200)) {
      names.push(key, ...propertyNames(child, depth - 1));
    }
  }
  if (node.items) names.push(...propertyNames(node.items, depth));
  return names;
}

function classFromAnnotations(annotations?: Record<string, unknown>): ToolClass | undefined {
  if (!annotations) {
    return undefined;
  }
  if (annotations.destructiveHint === true || annotations.openWorldHint === true) {
    return "sink";
  }
  if (annotations.readOnlyHint === true) {
    return "source";
  }
  return undefined;
}

function capabilitiesFromAnnotations(annotations?: Record<string, unknown>): ToolCapability[] {
  if (!annotations) {
    return [];
  }
  const capabilities = new Set<ToolCapability>();
  if (annotations.destructiveHint === true) {
    capabilities.add("writes_remote");
    capabilities.add("file_write");
    capabilities.add("writes_local");
  }
  if (annotations.openWorldHint === true) {
    capabilities.add("network_egress");
    capabilities.add("reads_untrusted_content");
  }
  if (annotations.readOnlyHint === true) {
    capabilities.add("reads_untrusted_content");
  }
  return [...capabilities];
}

function deriveClass(toolName: string, capabilities: Set<ToolCapability>, sourceEvidence: boolean): ToolClass {
  if ([...capabilities].some((capability) => [
    "network_egress",
    "file_write",
    "writes_local",
    "writes_remote",
    "persists_memory",
    "deletes_data",
    "executes_code",
    "sends_message",
    "accesses_credentials",
    "invokes_model"
  ].includes(capability))) {
    return "sink";
  }
  if (sourceEvidence || SOURCE_RE.test(toolName)) {
    return "source";
  }
  if (SINK_RE.test(toolName)) {
    return "sink";
  }
  return "unknown";
}
