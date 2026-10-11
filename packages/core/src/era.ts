import { isRequest, type JsonRpcMessage } from "./mcp.js";
import { protocolVersionOf } from "./http.js";

export type McpEra = "2026-07-28" | "legacy";

export function detectEra(message: JsonRpcMessage): McpEra | undefined {
  if (isRequest(message) && message.method === "initialize") {
    return "legacy";
  }
  if (protocolVersionOf(message) !== undefined) {
    return "2026-07-28";
  }
  return undefined;
}

export const PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion";

export function isServerNotification(message: JsonRpcMessage): boolean {
  return "method" in message && (message as { method: string }).method.startsWith("notifications/") && !("id" in message);
}

export function isToolsListChanged(message: JsonRpcMessage): boolean {
  return isServerNotification(message) && (message as { method: string }).method === "notifications/tools/list_changed";
}

export const SENSITIVE_FIELD_NAME_RE = /(password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|payment|card|credit|ccv|cvv|cvc|ssn|social[_-]?security|access[_-]?key|auth[_-]?token)/iu;
