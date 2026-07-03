import { createHash } from "node:crypto";
import type { McpTool } from "./mcp.js";

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function hashTool(tool: McpTool): string {
  return hashDescriptor({
    name: tool.name,
    title: tool.title ?? "",
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
    outputSchema: tool.outputSchema ?? {},
    annotations: tool.annotations ?? {},
    icons: tool.icons ?? [],
    _meta: tool._meta ?? {}
  });
}

export function hashDescriptor(value: unknown): string {
  return sha256(stableStringify(value));
}
