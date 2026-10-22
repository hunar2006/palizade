import type { ToolCapability, ToolClass } from "@palizade/policy";
import type { ArgumentRole } from "./arguments.js";
import type { ServerConfig } from "./config.js";

// Curated classes for widely used MCP servers. The catalog is chosen by what the user put in
// their config (package name, image or url), never by anything the server says about itself.
// Tools a server adds later fall through to the heuristics, and the lockfile flags the change.

export interface CatalogRule {
  tools: RegExp;
  toolClass: ToolClass;
  capabilities: ToolCapability[];
  roles?: Record<string, ArgumentRole>;
}

export interface CatalogEntry {
  id: string;
  title: string;
  identifiers: RegExp;
  rules: CatalogRule[];
}

export interface CatalogMatch {
  entry: CatalogEntry;
  rule: CatalogRule;
}

const READS: ToolCapability[] = ["reads_untrusted_content"];
const REMOTE_WRITE: ToolCapability[] = ["writes_remote", "network_egress"];
const MESSAGE: ToolCapability[] = ["sends_message", "writes_remote", "network_egress"];
const LOCAL_WRITE: ToolCapability[] = ["file_write", "writes_local"];
const BROWSE: ToolCapability[] = ["network_egress", "reads_untrusted_content"];
const FILE_ROLES: Record<string, ArgumentRole> = { path: "file_path", source: "file_path", destination: "file_path", "paths[*]": "file_path" };
const GITHUB_ROLES: Record<string, ArgumentRole> = { owner: "account_id", repo: "repository_destination" };

export const TOOL_CATALOG: CatalogEntry[] = [
  {
    id: "filesystem",
    title: "MCP filesystem server",
    identifiers: /@modelcontextprotocol\/server-filesystem|\bmcp\/filesystem\b/iu,
    rules: [
      { tools: /^(read_file|read_text_file|read_media_file|read_multiple_files|list_directory|list_directory_with_sizes|directory_tree|search_files|get_file_info)$/u, toolClass: "source", capabilities: READS, roles: FILE_ROLES },
      { tools: /^list_allowed_directories$/u, toolClass: "pure", capabilities: [] },
      { tools: /^(write_file|edit_file|create_directory)$/u, toolClass: "sink", capabilities: LOCAL_WRITE, roles: FILE_ROLES },
      { tools: /^move_file$/u, toolClass: "sink", capabilities: [...LOCAL_WRITE, "deletes_data"], roles: FILE_ROLES }
    ]
  },
  {
    id: "fetch",
    title: "MCP fetch server",
    identifiers: /\bmcp-server-fetch\b|@modelcontextprotocol\/server-fetch|\bmcp\/fetch\b/iu,
    rules: [{ tools: /^fetch$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } }]
  },
  {
    id: "memory",
    title: "MCP knowledge graph memory server",
    identifiers: /@modelcontextprotocol\/server-memory|\bmcp\/memory\b/iu,
    rules: [
      { tools: /^(read_graph|search_nodes|open_nodes)$/u, toolClass: "source", capabilities: READS },
      { tools: /^(create_entities|create_relations|add_observations)$/u, toolClass: "sink", capabilities: ["persists_memory", "writes_remote"] },
      { tools: /^delete_(entities|observations|relations)$/u, toolClass: "sink", capabilities: ["persists_memory", "deletes_data"] }
    ]
  },
  {
    id: "git",
    title: "MCP git server",
    identifiers: /\bmcp-server-git\b|\bmcp\/git\b/iu,
    rules: [
      { tools: /^git_(status|diff_unstaged|diff_staged|diff|log|show|branch)$/u, toolClass: "source", capabilities: READS, roles: { repo_path: "file_path" } },
      { tools: /^git_(add|commit|reset|create_branch|checkout|init)$/u, toolClass: "sink", capabilities: LOCAL_WRITE, roles: { repo_path: "file_path" } }
    ]
  },
  {
    id: "github",
    title: "GitHub MCP server",
    identifiers: /github-mcp-server|@modelcontextprotocol\/server-github|api\.githubcopilot\.com/iu,
    rules: [
      { tools: /^(get|list|search)_|^get_me$/u, toolClass: "source", capabilities: READS, roles: GITHUB_ROLES },
      { tools: /^delete_/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "deletes_data"], roles: GITHUB_ROLES },
      { tools: /^(create|update|merge|push|add|fork|request|assign|submit|dismiss|mark|manage|run|rerun|cancel|star|unstar|remove|reprioritize|sub_issue)_/u, toolClass: "sink", capabilities: REMOTE_WRITE, roles: GITHUB_ROLES }
    ]
  },
  {
    id: "slack",
    title: "Slack MCP server",
    identifiers: /@modelcontextprotocol\/server-slack|\bslack-mcp-server\b|\bmcp\/slack\b/iu,
    rules: [
      { tools: /^slack_(list_channels|get_channel_history|get_thread_replies|get_users|get_user_profile)$/u, toolClass: "source", capabilities: READS, roles: { channel_id: "channel_id" } },
      { tools: /^slack_(post_message|reply_to_thread|add_reaction)$/u, toolClass: "sink", capabilities: MESSAGE, roles: { channel_id: "channel_id" } }
    ]
  },
  {
    id: "puppeteer",
    title: "Puppeteer MCP server",
    identifiers: /@modelcontextprotocol\/server-puppeteer|\bmcp\/puppeteer\b/iu,
    rules: [
      { tools: /^puppeteer_navigate$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^puppeteer_screenshot$/u, toolClass: "source", capabilities: READS },
      { tools: /^puppeteer_evaluate$/u, toolClass: "sink", capabilities: ["executes_code", "network_egress"] },
      { tools: /^puppeteer_(click|fill|select|hover)$/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "playwright",
    title: "Playwright MCP server",
    identifiers: /@playwright\/mcp|\bmcp\/playwright\b/iu,
    rules: [
      { tools: /^browser_(navigate|navigate_back|navigate_forward)$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^browser_(snapshot|take_screenshot|console_messages|network_requests|network_request|wait_for|find)$/u, toolClass: "source", capabilities: READS },
      { tools: /^browser_(evaluate|run_code|run_code_unsafe)$/u, toolClass: "sink", capabilities: ["executes_code", "network_egress"] },
      { tools: /^browser_(file_upload|drop)$/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "reads_sensitive_data"] },
      { tools: /^browser_tabs$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^browser_(click|type|fill_form|select_option|press_key|drag|hover|handle_dialog|emulate_media)$/u, toolClass: "sink", capabilities: REMOTE_WRITE },
      { tools: /^browser_(close|resize|install)$/u, toolClass: "pure", capabilities: [] }
    ]
  },
  {
    id: "brave-search",
    title: "Brave Search MCP server",
    identifiers: /@modelcontextprotocol\/server-brave-search|@brave\/brave-search-mcp-server|\bmcp\/brave-search\b/iu,
    rules: [{ tools: /^brave_\w*search$/u, toolClass: "source", capabilities: READS }]
  },
  {
    id: "time",
    title: "MCP time server",
    identifiers: /\bmcp-server-time\b|\bmcp\/time\b/iu,
    rules: [{ tools: /^(get_current_time|convert_time)$/u, toolClass: "pure", capabilities: [] }]
  },
  {
    id: "sequential-thinking",
    title: "MCP sequential thinking server",
    identifiers: /@modelcontextprotocol\/server-sequential-thinking|\bmcp\/sequentialthinking\b/iu,
    rules: [{ tools: /^sequentialthinking$/u, toolClass: "pure", capabilities: [] }]
  }
];

/** Finds the catalog entry for a configured server from its command, args, docker image or url. */
export function catalogEntryFor(server: Pick<ServerConfig, "command" | "args" | "url"> & { catalog?: string | false | undefined }): CatalogEntry | undefined {
  if (server.catalog === false) return undefined;
  if (typeof server.catalog === "string") return TOOL_CATALOG.find((entry) => entry.id === server.catalog);
  const identity = [server.command ?? "", ...(server.args ?? []), server.url ?? ""].join(" ");
  return TOOL_CATALOG.find((entry) => entry.identifiers.test(identity));
}

export function catalogMatch(toolName: string, server: Parameters<typeof catalogEntryFor>[0]): CatalogMatch | undefined {
  const entry = catalogEntryFor(server);
  const rule = entry?.rules.find((candidate) => candidate.tools.test(toolName));
  return entry && rule ? { entry, rule } : undefined;
}
