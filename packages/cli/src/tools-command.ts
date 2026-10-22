import { catalogEntryFor, classifyToolDetailed, TOOL_CATALOG, type McpTool, type PalizadeConfig, type PalizadeLock } from "@palizade/core";

export interface ToolRow {
  server: string;
  tool: string;
  toolClass: string;
  capabilities: string[];
  reasons: string[];
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
      return { server: name, tool: toolName, toolClass: classification.toolClass, capabilities: classification.capabilities, reasons: classification.reasons };
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
    }
    const unknown = report.tools.filter((row) => row.toolClass === "unknown").length;
    if (unknown > 0) {
      lines.push(`  ${unknown} unknown tool(s): ${report.trust === "untrusted" ? "blocked" : report.trust === "semi" ? "need approval" : "logged"} by the default policy; set toolClasses for them in palizade.yaml`);
    }
  }
  return lines.join("\n");
}

export function formatCatalog(): string {
  return TOOL_CATALOG.map((entry) => `${entry.id.padEnd(20)} ${entry.title}  matches ${entry.identifiers.source}`).join("\n");
}
