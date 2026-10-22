import { parse, stringify } from "smol-toml";

// Codex keeps MCP servers in TOML ([mcp_servers.<name>] tables). Palizade reads them into the
// same shape as the JSON clients, and on write replaces only the tables of servers it changed,
// so the rest of the file (comments included) stays as the user wrote it.

type JsonRecord = Record<string, unknown>;

export interface CodexState {
  text: string;
  tables: Record<string, JsonRecord>;
  before: Record<string, string>;
}

const TRANSPORT_KEYS = ["command", "args", "env", "cwd", "url", "bearer_token_env_var", "http_headers", "env_http_headers", "auth", "http_headers_helper", "experimental_environment"];

export function parseCodexConfig(text: string, path: string): { mcpServers: JsonRecord; state: CodexState } {
  let parsed: JsonRecord;
  try {
    parsed = parse(text) as JsonRecord;
  } catch (error) {
    throw new Error(`Failed to parse client config at ${path}: ${error instanceof Error ? error.message : String(error)}. Refusing to overwrite it.`);
  }
  const servers = isRecord(parsed.mcp_servers) ? parsed.mcp_servers : {};
  const tables: Record<string, JsonRecord> = {};
  const mcpServers: JsonRecord = {};
  for (const [name, table] of Object.entries(servers)) {
    if (!isRecord(table)) continue;
    tables[name] = table;
    mcpServers[name] = codexToClientEntry(table);
  }
  return { mcpServers, state: { text, tables, before: Object.fromEntries(Object.entries(mcpServers).map(([name, entry]) => [name, JSON.stringify(entry)])) } };
}

/** Maps a Codex table to the JSON client shape; credentials become ${VAR} headers. */
export function codexToClientEntry(table: JsonRecord): JsonRecord {
  if (typeof table.url === "string") {
    const headers: Record<string, string> = {};
    if (isRecord(table.http_headers)) for (const [key, value] of Object.entries(table.http_headers)) if (typeof value === "string") headers[key] = value;
    if (isRecord(table.env_http_headers)) for (const [key, value] of Object.entries(table.env_http_headers)) if (typeof value === "string") headers[key] = `\${${value}}`;
    if (typeof table.bearer_token_env_var === "string") headers.Authorization = `Bearer \${${table.bearer_token_env_var}}`;
    return { type: "http", url: table.url, ...(Object.keys(headers).length > 0 ? { headers } : {}) };
  }
  return {
    ...(typeof table.command === "string" ? { command: table.command } : {}),
    ...(Array.isArray(table.args) ? { args: table.args } : {}),
    ...(typeof table.cwd === "string" ? { cwd: table.cwd } : {}),
    ...(isRecord(table.env) ? { env: table.env } : {})
  };
}

/** Rewrites the tables of servers whose entry changed and appends new ones. */
export function renderCodexConfig(state: CodexState, mcpServers: JsonRecord): string {
  let text = state.text;
  const blocks: string[] = [];
  for (const [name, entry] of Object.entries(mcpServers)) {
    if (state.before[name] === JSON.stringify(entry) || !isRecord(entry)) continue;
    const original = state.tables[name] ?? {};
    const kept = Object.fromEntries(Object.entries(original).filter(([key]) => !TRANSPORT_KEYS.includes(key)));
    // Codex passes only listed variables to a server, so forward every name the original used.
    const forwarded = new Set<string>(Array.isArray(original.env_vars) ? original.env_vars.filter((value): value is string => typeof value === "string") : []);
    for (const value of Object.values(isRecord(original.env_http_headers) ? original.env_http_headers : {})) if (typeof value === "string") forwarded.add(value);
    if (typeof original.bearer_token_env_var === "string") forwarded.add(original.bearer_token_env_var);
    const objectVars = Array.isArray(original.env_vars) ? original.env_vars.filter((value) => typeof value !== "string") : [];
    const envVars = [...forwarded, ...objectVars];
    const table: JsonRecord = { command: entry.command, args: entry.args, ...kept, ...(envVars.length > 0 ? { env_vars: envVars } : {}) };
    if (name in state.tables) {
      const removed = removeServerTables(text, name);
      if (removed === undefined) {
        throw new Error(`Server '${name}' in the Codex config is not written as its own [mcp_servers.${name}] table; change it by hand.`);
      }
      text = removed;
    }
    blocks.push(stringify({ mcp_servers: { [name]: table } }).trim());
  }
  if (blocks.length === 0) return text;
  return `${text.replace(/\s*$/u, "")}${text.trim() ? "\n\n" : ""}${blocks.join("\n\n")}\n`;
}

/** Removes [mcp_servers.<name>] and its sub tables; undefined when the server is not defined that way. */
export function removeServerTables(text: string, name: string): string | undefined {
  const lines = text.split(/\r?\n/u);
  const header = /^\s*\[\s*([^\]]+?)\s*\]\s*(#.*)?$/u;
  const keyForms = [name, `"${name}"`, `'${name}'`];
  const ours = (path: string) => keyForms.some((form) => path === `mcp_servers.${form}` || path.startsWith(`mcp_servers.${form}.`));
  const out: string[] = [];
  let skipped: string[] = [];
  let skipping = false;
  let found = false;
  for (const line of lines) {
    const match = header.exec(line);
    if (match && !line.trim().startsWith("[[")) {
      const next = ours(match[1]!.replace(/\s*\.\s*/gu, "."));
      if (skipping && !next) {
        // Comments right above the next table belong to it, not to the removed one.
        let start = skipped.length;
        while (start > 0 && /^\s*(#.*)?$/u.test(skipped[start - 1]!)) start -= 1;
        out.push(...skipped.slice(start));
      }
      skipping = next;
      skipped = [];
      if (skipping) found = true;
    }
    if (skipping) skipped.push(line);
    else out.push(line);
  }
  if (!found) return undefined;
  const result = out.join("\n");
  const reparsed = parse(result) as JsonRecord;
  return isRecord(reparsed.mcp_servers) && name in reparsed.mcp_servers ? undefined : result;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
