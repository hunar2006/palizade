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
  /** The server is known to mark these read tools destructive (for example every POST), so the hint does not raise them. */
  ignoreDestructiveHint?: true;
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
    rules: [{ tools: /^brave_(\w*search|summarizer|llm_context)$/u, toolClass: "source", capabilities: READS }]
  },
  {
    id: "notion",
    title: "Notion MCP server (local)",
    identifiers: /@notionhq\/notion-mcp-server/iu,
    rules: [
      // Search and data source queries are POST requests that only read.
      { tools: /^API-(get-|retrieve-|list-)/u, toolClass: "source", capabilities: READS },
      { tools: /^API-(post-search|query-data-source)$/u, toolClass: "source", capabilities: READS, ignoreDestructiveHint: true },
      { tools: /^API-delete-/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "deletes_data"] },
      { tools: /^API-(patch-|post-page$|update-|create-|move-page$)/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "context7",
    title: "Context7 documentation server",
    identifiers: /@upstash\/context7-mcp|mcp\.context7\.com/iu,
    rules: [{ tools: /^(resolve-library-id|query-docs|get-library-docs)$/u, toolClass: "source", capabilities: READS }]
  },
  {
    id: "firecrawl",
    title: "Firecrawl MCP server",
    identifiers: /\bfirecrawl-mcp\b|mcp\.firecrawl\.dev/iu,
    rules: [
      { tools: /^firecrawl_(scrape|map|crawl|interact)$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^firecrawl_agent$/u, toolClass: "sink", capabilities: BROWSE, roles: { "urls[*]": "url" } },
      { tools: /^firecrawl_(search|check_crawl_status|agent_status|find_tools|credit_usage|developer_search|gov_search|research_\w+|monitor_(list|get|checks|check))$/u, toolClass: "source", capabilities: READS },
      // Uploads a local file to Firecrawl for parsing.
      { tools: /^firecrawl_parse$/u, toolClass: "sink", capabilities: ["network_egress", "reads_sensitive_data"], roles: { filePath: "file_path" } },
      { tools: /^firecrawl_monitor_create$/u, toolClass: "sink", capabilities: MESSAGE, roles: { email: "email_recipient", webhookUrl: "url" } },
      { tools: /^firecrawl_monitor_delete$/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "deletes_data"] },
      { tools: /^firecrawl_(monitor_update|monitor_run|feedback|search_feedback|interact_stop)$/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "exa",
    title: "Exa search server",
    identifiers: /\bexa-mcp-server\b|mcp\.exa\.ai/iu,
    rules: [
      { tools: /^web_search_exa$/u, toolClass: "source", capabilities: READS },
      { tools: /^web_fetch_exa$/u, toolClass: "sink", capabilities: BROWSE, roles: { "urls[*]": "url" } }
    ]
  },
  {
    id: "tavily",
    title: "Tavily search server",
    identifiers: /\btavily-mcp\b|mcp\.tavily\.com/iu,
    rules: [
      { tools: /^tavily_(search|research)$/u, toolClass: "source", capabilities: READS },
      { tools: /^tavily_extract$/u, toolClass: "sink", capabilities: BROWSE, roles: { "urls[*]": "url" } },
      { tools: /^tavily_(crawl|map)$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } }
    ]
  },
  {
    id: "sentry",
    title: "Sentry MCP server",
    identifiers: /@sentry\/mcp-server|mcp\.sentry\.dev/iu,
    rules: [
      { tools: /^(find_\w+|search_\w+|get_sentry_resource|analyze_issue_with_seer)$/u, toolClass: "source", capabilities: READS },
      { tools: /^(update_issue|execute_sentry_tool)$/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "postgres",
    title: "MCP Postgres server (read only queries)",
    identifiers: /@modelcontextprotocol\/server-postgres|\bmcp\/postgres\b/iu,
    rules: [{ tools: /^query$/u, toolClass: "source", capabilities: READS }]
  },
  {
    id: "chrome-devtools",
    title: "Chrome DevTools MCP server",
    identifiers: /\bchrome-devtools-mcp\b/iu,
    rules: [
      { tools: /^(navigate_page|new_page)$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^(take_snapshot|take_screenshot|take_heapsnapshot|list_console_messages|get_console_message|list_network_requests|get_network_request|list_pages|get_css_styles|performance_analyze_insight|lighthouse_audit|wait_for)$/u, toolClass: "source", capabilities: READS },
      { tools: /^evaluate_script$/u, toolClass: "sink", capabilities: ["executes_code", "network_egress"] },
      { tools: /^upload_file$/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "reads_sensitive_data"], roles: { "filePaths[*]": "file_path" } },
      { tools: /^(click|fill|fill_form|hover|drag|press_key|type_text|handle_dialog|emulate)$/u, toolClass: "sink", capabilities: REMOTE_WRITE },
      { tools: /^(performance_start_trace|performance_stop_trace|screencast_start)$/u, toolClass: "sink", capabilities: LOCAL_WRITE, roles: { filePath: "file_path" } },
      { tools: /^(select_page|close_page|resize_page|screencast_stop)$/u, toolClass: "pure", capabilities: [] }
    ]
  },
  {
    id: "heroku",
    title: "Heroku MCP server",
    identifiers: /@heroku\/mcp-server/iu,
    rules: [
      { tools: /^pg_credentials$/u, toolClass: "source", capabilities: ["accesses_credentials", "reads_sensitive_data"] },
      { tools: /^(list_\w+|get_\w+|pg_(info|ps|locks|outliers|maintenance|backups)|ps_list|pipelines_(list|info))$/u, toolClass: "source", capabilities: READS },
      { tools: /^(pg_psql|deploy_one_off_dyno)$/u, toolClass: "sink", capabilities: ["executes_code", "writes_remote", "network_egress"] },
      { tools: /^deploy_to_heroku$/u, toolClass: "sink", capabilities: REMOTE_WRITE, roles: { rootUri: "url", tarballUri: "url" } },
      { tools: /^pg_kill$/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "deletes_data"] },
      { tools: /^(create_app|rename_app|maintenance_on|maintenance_off|create_addon|ps_scale|ps_restart|pipelines_create|pipelines_promote|pg_upgrade)$/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "mongodb",
    title: "MongoDB MCP server",
    identifiers: /\bmongodb-mcp-server\b/iu,
    rules: [
      { tools: /^(aggregate|aggregate-db|collection-indexes|collection-schema|collection-storage-size|count|db-stats|explain|export|find|list-[\w-]+|mongodb-logs|search-knowledge)$/u, toolClass: "source", capabilities: READS },
      // A connection string from untrusted content could point at an attacker's database.
      { tools: /^connect$/u, toolClass: "sink", capabilities: ["network_egress"], roles: { connectionString: "url" } },
      { tools: /^disconnect$/u, toolClass: "pure", capabilities: [] },
      { tools: /^(delete-many|drop-collection|drop-database|drop-index)$/u, toolClass: "sink", capabilities: [...REMOTE_WRITE, "deletes_data"] },
      { tools: /^(create-collection|create-index|insert-many|update-many|rename-collection)$/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "browserbase",
    title: "Browserbase MCP server",
    identifiers: /@browserbasehq\/mcp-server-browserbase|\bmcp-server-browserbase\b/iu,
    rules: [
      { tools: /^browserbase_stagehand_navigate$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      { tools: /^browserbase_(stagehand_extract|stagehand_observe|screenshot|stagehand_get_url)$/u, toolClass: "source", capabilities: READS },
      { tools: /^browserbase_(stagehand_act|stagehand_agent)$/u, toolClass: "sink", capabilities: REMOTE_WRITE },
      { tools: /^browserbase_session_(create|close)$/u, toolClass: "pure", capabilities: [] }
    ]
  },
  {
    id: "figma",
    title: "Figma developer MCP server",
    identifiers: /\bfigma-developer-mcp\b/iu,
    rules: [
      { tools: /^get_figma_data$/u, toolClass: "source", capabilities: READS },
      { tools: /^download_figma_images$/u, toolClass: "sink", capabilities: LOCAL_WRITE, roles: { localPath: "file_path" } }
    ]
  },
  {
    id: "desktop-commander",
    title: "Desktop Commander MCP server",
    identifiers: /@wonderwhy-er\/desktop-commander/iu,
    rules: [
      // read_file also fetches urls (isUrl), so a path copied from untrusted content is checked.
      { tools: /^read_file$/u, toolClass: "sink", capabilities: BROWSE, roles: { path: "file_path" } },
      { tools: /^(get_config|read_multiple_files|list_directory|start_search|get_more_search_results|list_searches|get_file_info|read_process_output|list_sessions|list_processes|get_usage_stats|get_recent_tool_calls)$/u, toolClass: "source", capabilities: READS, roles: FILE_ROLES },
      { tools: /^(start_process|interact_with_process)$/u, toolClass: "sink", capabilities: ["executes_code", "network_egress", "writes_local"], roles: { command: "shell_command" } },
      { tools: /^move_file$/u, toolClass: "sink", capabilities: [...LOCAL_WRITE, "deletes_data"], roles: FILE_ROLES },
      { tools: /^(write_file|write_pdf|create_directory|edit_block)$/u, toolClass: "sink", capabilities: LOCAL_WRITE, roles: { ...FILE_ROLES, file_path: "file_path", outputPath: "file_path" } },
      { tools: /^(set_config_value|force_terminate|kill_process|stop_search)$/u, toolClass: "sink", capabilities: ["writes_local"] },
      { tools: /^give_feedback_to_desktop_commander$/u, toolClass: "sink", capabilities: ["network_egress"] }
    ]
  },
  {
    id: "gitlab",
    title: "MCP GitLab server",
    identifiers: /@modelcontextprotocol\/server-gitlab|\bmcp\/gitlab\b/iu,
    rules: [
      { tools: /^(search_repositories|get_file_contents)$/u, toolClass: "source", capabilities: READS },
      { tools: /^(create_or_update_file|create_repository|push_files|create_issue|create_merge_request|fork_repository|create_branch)$/u, toolClass: "sink", capabilities: REMOTE_WRITE, roles: { project_id: "repository_destination" } }
    ]
  },
  {
    id: "google-maps",
    title: "MCP Google Maps server",
    identifiers: /@modelcontextprotocol\/server-google-maps|\bmcp\/google-maps\b/iu,
    rules: [{ tools: /^maps_\w+$/u, toolClass: "source", capabilities: READS }]
  },
  {
    id: "hubspot",
    title: "HubSpot MCP server",
    identifiers: /@hubspot\/mcp-server/iu,
    rules: [
      { tools: /^hubspot-(get-|list-|search-|batch-read-)/u, toolClass: "source", capabilities: READS },
      { tools: /^hubspot-generate-feedback-link$/u, toolClass: "pure", capabilities: [] },
      { tools: /^hubspot-(batch-create-|batch-update-|create-|update-)/u, toolClass: "sink", capabilities: REMOTE_WRITE }
    ]
  },
  {
    id: "apify",
    title: "Apify Actors MCP server",
    identifiers: /@apify\/actors-mcp-server|mcp\.apify\.com/iu,
    rules: [
      { tools: /^(search-actors|fetch-actor-details|get-actor-run|get-dataset-items|get-key-value-store-record|search-apify-docs)$/u, toolClass: "source", capabilities: READS },
      { tools: /^fetch-apify-docs$/u, toolClass: "sink", capabilities: BROWSE, roles: { url: "url" } },
      // Actors are arbitrary cloud programs (scrapers, automations) run with the given input.
      { tools: /^call-actor$/u, toolClass: "sink", capabilities: ["executes_code", "writes_remote", "network_egress"] },
      { tools: /^abort-actor-run$/u, toolClass: "sink", capabilities: REMOTE_WRITE },
      { tools: /^report-problem$/u, toolClass: "sink", capabilities: MESSAGE }
    ]
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
