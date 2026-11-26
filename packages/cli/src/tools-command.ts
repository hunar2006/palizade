import { catalogEntryFor, classifyToolDetailed, TOOL_CATALOG, type ArgumentRole, type McpTool, type PalizadeConfig, type PalizadeLock } from "@palizade/core";

export interface ToolRow {
  server: string;
  tool: string;
  toolClass: string;
  capabilities: string[];
  reasons: string[];
  argumentRoles: Record<string, ArgumentRole>;
  suggestedArgumentRoles: Record<string, ArgumentRole>;
}

export interface ServerToolsReport {
  server: string;
  trust: string;
  catalog?: string | undefined;
  locked: boolean;
  tools: ToolRow[];
}

/** Classifies every locked tool without starting any server. */
export function describeServerTools(config: Pick<PalizadeConfig, "servers">, lock: PalizadeLock, only?: string): ServerToolsReport[] {
  const names = only ? [only] : Object.keys(config.servers);
  return names.map((name) => {
    const server = config.servers[name];
    if (!server) throw new Error(`Unknown server '${name}'.`);
    const locked = lock.servers[name]?.tools ?? {};
    const tools = Object.entries(locked).map(([toolName, entry]): ToolRow => {
      const snapshot = (entry.snapshot ?? { name: toolName }) as unknown as McpTool;
      const classification = classifyToolDetailed(toolName, server, { ...snapshot, name: toolName });
      const argumentRoles = { ...classification.argumentRoles, ...server.argumentRoles?.[toolName] };
      return {
        server: name, tool: toolName, toolClass: classification.toolClass,
        capabilities: classification.capabilities, reasons: classification.reasons, argumentRoles,
        suggestedArgumentRoles: suggestArgumentRoles(snapshot.inputSchema, argumentRoles)
      };
    });
    return { server: name, trust: server.trust, catalog: catalogEntryFor(server)?.id, locked: Object.keys(locked).length > 0, tools };
  });
}

export function formatServerTools(reports: ServerToolsReport[]): string {
  const lines: string[] = [];
  for (const report of reports) {
    lines.push(`${report.server} [trust=${report.trust}] [catalog=${report.catalog ?? "none"}]`);
    if (!report.locked) {
      lines.push(`  no locked tools; run palizade lock approve ${report.server}`);
      continue;
    }
    for (const row of report.tools) {
      lines.push(`  ${row.toolClass.padEnd(7)} ${row.tool}  ${row.capabilities.join(",") || "-"}  (${row.reasons.join(", ")})`);
      const roles = Object.entries(row.argumentRoles);
      if (roles.length > 0) lines.push(`    roles: ${roles.map(([field, role]) => `${JSON.stringify(field)}=${role}`).join(", ")}`);
      const suggestions = Object.entries(row.suggestedArgumentRoles);
      if (suggestions.length > 0) lines.push(`    roles to review from the locked schema: ${suggestions.map(([field, role]) => `${JSON.stringify(field)}=${role}`).join(", ")}`);
    }
    const unknown = report.tools.filter((row) => row.toolClass === "unknown").length;
    if (unknown > 0) {
      lines.push(`  ${unknown} unknown tool(s): ${report.trust === "untrusted" ? "blocked" : report.trust === "semi" ? "need approval" : "logged"} by the default policy; set toolClasses for them in palizade.yaml`);
    }
  }
  return lines.join("\n");
}

const schemaRoles = new Map<string, ArgumentRole>([["email", "email_recipient"], ["hostname", "hostname"], ["uri", "url"]]);

function suggestArgumentRoles(schema: unknown, current: Record<string, ArgumentRole>): Record<string, ArgumentRole> {
  const properties = schema && typeof schema === "object" && (schema as { properties?: unknown }).properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) return {};
  const suggestions: Array<[string, ArgumentRole]> = [];
  for (const [name, item] of Object.entries(properties)) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(name) || !item || typeof item !== "object") continue;
    const fieldSchema = item as { type?: string; format?: string; items?: { type?: string; format?: string } };
    const field = fieldSchema.type === "array" ? `${name}[*]` : name;
    const value = fieldSchema.type === "array" ? fieldSchema.items : fieldSchema;
    const role = value?.type === "string" && value.format ? schemaRoles.get(value.format) : undefined;
    if (role && !Object.hasOwn(current, field) && !Object.hasOwn(current, `$.${field}`)) suggestions.push([field, role]);
  }
  return Object.fromEntries(suggestions);
}

export function formatCatalog(): string {
  return TOOL_CATALOG.map((entry) => `${entry.id.padEnd(20)} ${entry.title}  matches ${entry.identifiers.source}`).join("\n");
}
