import type { ToolCapability, ToolClass } from "@palizade/policy";
import type { McpTool } from "./mcp.js";
import type { ServerConfig } from "./config.js";

const SINK_RE = /\b(send|post|put|patch|delete|write|save|exec|shell|run|spawn|email|sms|publish|commit|push|upload|http|fetch|request|webhook)\b/iu;
const SOURCE_RE = /\b(read|get|fetch|search|browse|list|download|crawl|open|load|query|receive|inbox|issue|pull|web|url|file)\b/iu;
const CAPABILITY_RULES: Array<[RegExp, ToolCapability[]]> = [
  [/\b(fetch|http|post|put|patch|request|webhook|url|browser|crawl)\b/iu, ["network_egress", "reads_untrusted_content"]],
  [/\b(email|mail|send|sms|slack|discord|message|publish)\b/iu, ["sends_message", "writes_remote", "network_egress"]],
  [/\b(write|save|edit|create|move|append)\b/iu, ["file_write", "writes_local"]],
  [/\b(delete|remove|rm|destroy)\b/iu, ["deletes_data"]],
  [/\b(exec|shell|run|spawn|command|script|terminal)\b/iu, ["executes_code"]],
  [/\b(secret|credential|token|key|env|password)\b/iu, ["accesses_credentials", "reads_sensitive_data"]],
  [/\b(model|sample|llm|completion|chat)\b/iu, ["invokes_model"]],
  [/\b(read|get|list|search|browse|open|download|load|query|inbox|issue|pull|file)\b/iu, ["reads_untrusted_content"]]
];

export interface ToolClassification {
  toolClass: ToolClass;
  capabilities: ToolCapability[];
}

export function classifyTool(toolName: string, server: ServerConfig, tool?: McpTool): ToolClass {
  return classifyToolDetailed(toolName, server, tool).toolClass;
}

export function classifyToolDetailed(toolName: string, server: ServerConfig, tool?: McpTool): ToolClassification {
  const configured = server.toolClasses[toolName];
  const capabilities = new Set<ToolCapability>(server.toolCapabilities[toolName] ?? []);

  const annotationClass = classFromAnnotations(tool?.annotations);
  for (const capability of capabilitiesFromAnnotations(tool?.annotations)) {
    capabilities.add(capability);
  }

  const searchable = `${toolName} ${tool?.title ?? ""} ${tool?.description ?? ""}`.replace(/[_-]+/gu, " ");
  for (const [regex, matched] of CAPABILITY_RULES) {
    if (regex.test(searchable)) {
      matched.forEach((capability) => capabilities.add(capability));
    }
  }

  return {
    toolClass: configured ?? annotationClass ?? deriveClass(toolName, capabilities),
    capabilities: [...capabilities]
  };
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

function deriveClass(toolName: string, capabilities: Set<ToolCapability>): ToolClass {
  if ([...capabilities].some((capability) => [
    "network_egress",
    "file_write",
    "writes_local",
    "writes_remote",
    "deletes_data",
    "executes_code",
    "sends_message",
    "accesses_credentials",
    "invokes_model"
  ].includes(capability))) {
    return "sink";
  }
  if (capabilities.has("reads_untrusted_content") || SOURCE_RE.test(toolName)) {
    return "source";
  }
  if (SINK_RE.test(toolName)) {
    return "sink";
  }
  return "unknown";
}
