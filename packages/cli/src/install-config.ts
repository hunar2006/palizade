import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, platform as osPlatform } from "node:os";
import { basename, dirname, posix, resolve, win32 } from "node:path";
import YAML from "yaml";
import { normalizeEnvPlaceholders } from "@palizade/core";

type JsonRecord = Record<string, unknown>;

export interface OptionValueReader {
  getOptionValue(name: string): unknown;
  getOptionValueSource(name: string): string | undefined;
}

export interface InstallConfigOptions {
  serverName: string;
  client?: string | undefined;
  configPath?: string | undefined;
  clientConfigPath?: string | undefined;
  project?: boolean | undefined;
  local?: boolean | undefined;
  entryName?: string | undefined;
  dryRun?: boolean | undefined;
  force?: boolean | undefined;
  cwd?: string | undefined;
  cliPath?: string | undefined;
  nodePath?: string | undefined;
}

export interface InstallAllConfigOptions {
  client?: string | undefined;
  configPath?: string | undefined;
  clientConfigPath?: string | undefined;
  project?: boolean | undefined;
  local?: boolean | undefined;
  dryRun?: boolean | undefined;
  cwd?: string | undefined;
  cliPath?: string | undefined;
  nodePath?: string | undefined;
}

export interface InstallConfigResult {
  client: string;
  clientConfigPath: string;
  entryName: string;
  entry: ClientMcpServerEntry;
  existed: boolean;
  written: boolean;
  warnings: string[];
  configJson: string;
  backupPath?: string;
}

export interface ClientMcpServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  headers?: Record<string, string>;
  cwd?: string;
  env?: Record<string, string>;
}

export interface WrappedServerResult {
  name: string;
  entry: ClientMcpServerEntry;
  original: ClientMcpServerEntry;
  addedToPalizadeConfig: boolean;
}

export interface SkippedServerResult {
  name: string;
  reason: string;
}

export interface InstallAllConfigResult {
  client: string;
  clientConfigPath: string;
  palizadeConfigPath: string;
  existed: boolean;
  written: boolean;
  clientConfigWritten: boolean;
  palizadeConfigWritten: boolean;
  warnings: string[];
  configJson: string;
  palizadeConfigJson: string;
  wrapped: WrappedServerResult[];
  skipped: SkippedServerResult[];
  lockCommands: string[];
  backupPath?: string;
}

export interface ClientCoverageRow {
  name: string;
  wrapped: boolean;
  command: string;
  advice?: string;
}

export interface ClientCoverageResult {
  client: string;
  clientConfigPath: string;
  existed: boolean;
  rows: ClientCoverageRow[];
  warnings: string[];
  nativeToolsNote?: string;
}

export async function installClientConfig(options: InstallConfigOptions): Promise<InstallConfigResult> {
  const client = options.client ?? "claude-desktop";
  const cwd = options.cwd ?? process.cwd();
  const clientConfigPath = options.clientConfigPath
    ? resolve(cwd, options.clientConfigPath)
    : resolveClientConfigPath(client, osPlatform(), process.env, homedir(), options.project ? cwd : undefined);
  const localKey = localScopeKey(client, options.local, cwd);
  const palizadeConfigPath = resolvePalizadeConfigPath(options.configPath, cwd);
  const entryName = options.entryName ?? `palizade-${options.serverName}`;
  const entry = makeEntry({
    serverName: options.serverName,
    palizadeConfigPath,
    cliPath: options.cliPath,
    nodePath: options.nodePath
  });
  const warnings = await validatePalizadeConfig(palizadeConfigPath);

  const existed = await exists(clientConfigPath);
  const config = existed ? await readClientConfig(clientConfigPath) : { mcpServers: {} };
  const mcpServers = ensureMcpServers(config, clientConfigPath, localKey, true);
  if (Object.prototype.hasOwnProperty.call(mcpServers, entryName) && !options.force) {
    throw new Error(
      `MCP server entry '${entryName}' already exists in ${clientConfigPath}. ` +
      `Use --force to overwrite it.\nExisting entry:\n${JSON.stringify(mcpServers[entryName], null, 2)}`
    );
  }

  mcpServers[entryName] = entry;
  const configJson = `${JSON.stringify(config, null, 2)}\n`;
  if (options.dryRun) {
    return {
      client,
      clientConfigPath,
      entryName,
      entry,
      existed,
      written: false,
      warnings,
      configJson
    };
  }

  await mkdir(dirname(clientConfigPath), { recursive: true });
  if (existed) {
    const backupPath = `${clientConfigPath}.bak`;
    await copyFile(clientConfigPath, backupPath);
    await writeFile(clientConfigPath, configJson, "utf8");
    return {
      client,
      clientConfigPath,
      entryName,
      entry,
      existed,
      written: true,
      warnings,
      configJson,
      backupPath
    };
  }

  await writeFile(clientConfigPath, configJson, "utf8");
  return {
    client,
    clientConfigPath,
    entryName,
    entry,
    existed,
    written: true,
    warnings,
    configJson
  };
}

export async function installAllClientConfigs(options: InstallAllConfigOptions): Promise<InstallAllConfigResult> {
  const client = options.client ?? "claude-desktop";
  const cwd = options.cwd ?? process.cwd();
  const clientConfigPath = options.clientConfigPath
    ? resolve(cwd, options.clientConfigPath)
    : resolveClientConfigPath(client, osPlatform(), process.env, homedir(), options.project ? cwd : undefined);
  const localKey = localScopeKey(client, options.local, cwd);
  const palizadeConfigPath = resolvePalizadeConfigPath(options.configPath, cwd);
  const cliPath = options.cliPath ?? getRunningCliPath();
  const warnings = await validatePalizadeConfig(palizadeConfigPath);

  const existed = await exists(clientConfigPath);
  const config = existed ? await readClientConfig(clientConfigPath) : { mcpServers: {} };
  const mcpServers = ensureMcpServers(config, clientConfigPath, localKey);

  const palizadeConfig = await readPalizadeConfig(palizadeConfigPath);
  const palizadeServers = ensurePalizadeServers(palizadeConfig, palizadeConfigPath);

  const wrapped: WrappedServerResult[] = [];
  const skipped: SkippedServerResult[] = [];

  for (const [name, rawEntry] of Object.entries(mcpServers)) {
    if (isPalizadeWrapper(rawEntry)) {
      skipped.push({ name, reason: "already wrapped by Palizade" });
      continue;
    }

    const unsupported = unsupportedTransport(rawEntry);
    if (unsupported) {
      skipped.push({ name, reason: `uses the '${unsupported}' transport, which Palizade cannot proxy; only stdio and Streamable HTTP servers are wrapped` });
      continue;
    }
    const original = normalizeClientEntry(name, rawEntry, clientConfigPath);
    const addedToPalizadeConfig = !Object.prototype.hasOwnProperty.call(palizadeServers, name);
    if (addedToPalizadeConfig) {
      palizadeServers[name] = makeAutoServerConfig(original);
    } else {
      warnings.push(`Warning: Palizade config already has a server named '${name}'; leaving that server definition unchanged.`);
    }

    const entry = makeEntry({
      serverName: name,
      palizadeConfigPath,
      cliPath,
      nodePath: options.nodePath
    });
    mcpServers[name] = entry;
    wrapped.push({ name, entry, original, addedToPalizadeConfig });
  }

  const configJson = `${JSON.stringify(config, null, 2)}\n`;
  const palizadeConfigJson = YAML.stringify(palizadeConfig);
  const lockCommands = wrapped
    .filter((server) => server.addedToPalizadeConfig)
    .map((server) => makeLockApproveCommand({
      nodePath: options.nodePath ?? process.execPath,
      cliPath,
      palizadeConfigPath,
      serverName: server.name
    }));

  if (options.dryRun || wrapped.length === 0) {
    return {
      client,
      clientConfigPath,
      palizadeConfigPath,
      existed,
      written: false,
      clientConfigWritten: false,
      palizadeConfigWritten: false,
      warnings,
      configJson,
      palizadeConfigJson,
      wrapped,
      skipped,
      lockCommands
    };
  }

  await mkdir(dirname(clientConfigPath), { recursive: true });
  let backupPath: string | undefined;
  if (existed) {
    backupPath = `${clientConfigPath}.bak`;
    await copyFile(clientConfigPath, backupPath);
  }
  await writeFile(clientConfigPath, configJson, "utf8");

  const palizadeConfigWritten = wrapped.some((server) => server.addedToPalizadeConfig);
  if (palizadeConfigWritten) {
    await mkdir(dirname(palizadeConfigPath), { recursive: true });
    await writeFile(palizadeConfigPath, palizadeConfigJson, "utf8");
  }

  return {
    client,
    clientConfigPath,
    palizadeConfigPath,
    existed,
    written: true,
    clientConfigWritten: true,
    palizadeConfigWritten,
    warnings,
    configJson,
    palizadeConfigJson,
    wrapped,
    skipped,
    lockCommands,
    ...(backupPath ? { backupPath } : {})
  };
}

export async function inspectClientCoverage(options: {
  client?: string | undefined;
  clientConfigPath?: string | undefined;
  project?: boolean | undefined;
  local?: boolean | undefined;
  cwd?: string | undefined;
}): Promise<ClientCoverageResult> {
  const client = options.client ?? "claude-desktop";
  const cwd = options.cwd ?? process.cwd();
  const clientConfigPath = options.clientConfigPath
    ? resolve(cwd, options.clientConfigPath)
    : resolveClientConfigPath(client, osPlatform(), process.env, homedir(), options.project ? cwd : undefined);
  const localKey = localScopeKey(client, options.local, cwd);

  if (!await exists(clientConfigPath)) {
    return {
      client,
      clientConfigPath,
      existed: false,
      rows: [],
      warnings: [`Client config not found: ${clientConfigPath}`],
      ...(isClaudeCodeClientPath(clientConfigPath) ? { nativeToolsNote: claudeCodeNativeToolsNote() } : {})
    };
  }

  const config = await readClientConfig(clientConfigPath);
  const mcpServers = ensureMcpServers(config, clientConfigPath, localKey);
  const rows = Object.entries(mcpServers).map(([name, rawEntry]): ClientCoverageRow => {
    const wrapped = isPalizadeWrapper(rawEntry);
    const command = isRecord(rawEntry) && typeof rawEntry.command === "string"
      ? rawEntry.command
      : isRecord(rawEntry) && typeof rawEntry.url === "string"
        ? `url=${rawEntry.url}`
        : "<invalid>";
    return {
      name,
      wrapped,
      command,
      ...(wrapped ? {} : {
        advice: unsupportedTransport(rawEntry)
          ? `WARNING: ${name} uses the '${unsupportedTransport(rawEntry)}' transport, which Palizade cannot proxy; it is NOT protected`
          : `WARNING: ${name} is configured but NOT protected by Palizade - run palizade install-config --all`
      })
    };
  });

  return {
    client,
    clientConfigPath,
    existed: true,
    rows,
    warnings: rows.filter((row) => !row.wrapped).map((row) => row.advice ?? ""),
    ...(isClaudeCodeClientPath(clientConfigPath) ? { nativeToolsNote: claudeCodeNativeToolsNote() } : {})
  };
}

export function selectInstallConfigPath(commandOptions: OptionValueReader, rootOptions: OptionValueReader): string | undefined {
  return cliOptionValue(commandOptions, "config") ?? cliOptionValue(rootOptions, "config");
}

export function resolvePalizadeConfigPath(configPath: string | undefined, cwd = process.cwd()): string {
  return resolve(cwd, configPath ?? "./palizade.yaml");
}

/** Pass projectDir to target a project's shared config (.mcp.json, .cursor/mcp.json) instead of the user's. */
export function resolveClientConfigPath(client: string, platform = osPlatform(), env: NodeJS.ProcessEnv = process.env, homeDir = homedir(), projectDir?: string): string {
  const join = platform === "win32" ? win32.join : posix.join;
  if (client === "claude-code") {
    // User scope lives at the top level of ~/.claude.json; project scope is .mcp.json.
    return projectDir ? join(projectDir, ".mcp.json") : join(homeDir, ".claude.json");
  }
  if (client === "cursor") {
    return projectDir ? join(projectDir, ".cursor", "mcp.json") : join(homeDir, ".cursor", "mcp.json");
  }
  if (client !== "claude-desktop") {
    throw new Error(`Unsupported client '${client}'. Supported clients: claude-desktop, claude-code, cursor. For Codex, see the README.`);
  }
  if (projectDir) {
    throw new Error("Claude Desktop has no project config; drop --project.");
  }
  if (platform === "win32") {
    if (!env.APPDATA) {
      throw new Error("APPDATA is not set; use --client-config to provide the Claude Desktop config path.");
    }
    return win32.join(env.APPDATA, "Claude", "claude_desktop_config.json");
  }
  if (platform === "darwin") {
    return posix.join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  return posix.join(homeDir, ".config", "Claude", "claude_desktop_config.json");
}

export function getRunningCliPath(argv1 = process.argv[1]): string {
  if (argv1 && argv1.trim() !== "") {
    return resolve(argv1);
  }
  throw new Error("Unable to determine the running Palizade CLI path.");
}

export function isPalizadeWrapper(value: unknown): boolean {
  if (!isRecord(value) || typeof value.command !== "string") {
    return false;
  }
  const args = Array.isArray(value.args) ? value.args.filter((arg): arg is string => typeof arg === "string") : [];
  const tokens = [value.command, ...args];
  if (!tokens.includes("wrap")) {
    return false;
  }
  return tokens.some(isLikelyPalizadeCliToken);
}

function cliOptionValue(options: OptionValueReader, name: string): string | undefined {
  const source = options.getOptionValueSource(name);
  if (!source || source === "default") {
    return undefined;
  }
  const value = options.getOptionValue(name);
  return typeof value === "string" ? value : undefined;
}

async function readClientConfig(path: string): Promise<JsonRecord> {
  const raw = await readFile(path, "utf8");
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) {
      throw new Error("top-level JSON value must be an object");
    }
    return parsed;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse client config at ${path}: ${reason}. Refusing to overwrite it.`);
  }
}

// Claude Code's default "local" scope keeps servers under projects[<project dir>] in ~/.claude.json.
function localScopeKey(client: string, local: boolean | undefined, cwd: string): string | undefined {
  if (!local) return undefined;
  if (client !== "claude-code") throw new Error("--local applies only to --client claude-code.");
  return resolve(cwd);
}

function findProjectKey(projects: JsonRecord, dir: string): string | undefined {
  // Keys may use either slash style on Windows, and drive letter case can differ.
  const normalize = (value: string) => value.replace(/\\/gu, "/").replace(/\/+$/u, "").toLowerCase();
  return Object.keys(projects).find((key) => normalize(key) === normalize(dir));
}

function ensureMcpServers(config: JsonRecord, path: string, localKey?: string, requireLocal = false): JsonRecord {
  if (localKey !== undefined) {
    const projects = isRecord(config.projects) ? config.projects : undefined;
    const key = projects ? findProjectKey(projects, localKey) : undefined;
    if (!projects || !key || !isRecord(projects[key])) {
      if (requireLocal) throw new Error(`${path} has no Claude Code project entry for ${localKey}. Open Claude Code in that directory once, or use --project.`);
      // Nothing to wrap: Claude Code has no local scope entry for this directory.
      return {};
    }
    return ensureMcpServers(projects[key] as JsonRecord, `${path} projects["${key}"]`);
  }
  const existing = config.mcpServers;
  if (existing === undefined) {
    const mcpServers: JsonRecord = {};
    config.mcpServers = mcpServers;
    return mcpServers;
  }
  if (!isRecord(existing)) {
    throw new Error(`Expected mcpServers in ${path} to be an object. Refusing to overwrite it.`);
  }
  return existing;
}

function makeEntry(options: { serverName: string; palizadeConfigPath: string; cliPath?: string | undefined; nodePath?: string | undefined }): ClientMcpServerEntry {
  const cliPath = resolve(options.cliPath ?? getRunningCliPath());
  const nodePath = options.nodePath ?? process.execPath;
  return {
    command: nodePath,
    args: [cliPath, "wrap", options.serverName, "-c", options.palizadeConfigPath]
  };
}

async function readPalizadeConfig(path: string): Promise<JsonRecord> {
  if (!await exists(path)) {
    return { servers: {} };
  }
  const raw = await readFile(path, "utf8");
  try {
    const parsed: unknown = YAML.parse(raw) ?? {};
    if (!isRecord(parsed)) {
      throw new Error("top-level YAML value must be an object");
    }
    return parsed;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse Palizade config at ${path}: ${reason}. Refusing to overwrite it.`);
  }
}

function ensurePalizadeServers(config: JsonRecord, path: string): JsonRecord {
  const existing = config.servers;
  if (existing === undefined) {
    const servers: JsonRecord = {};
    config.servers = servers;
    return servers;
  }
  if (!isRecord(existing)) {
    throw new Error(`Expected servers in ${path} to be an object. Refusing to overwrite it.`);
  }
  return existing;
}

function normalizeClientEntry(name: string, value: unknown, path: string): ClientMcpServerEntry {
  if (!isRecord(value)) {
    throw new Error(`Expected mcpServers.${name} in ${path} to be an object.`);
  }
  const entry: ClientMcpServerEntry = {};
  if (typeof value.url === "string" && value.url.trim() !== "") {
    entry.url = normalizeEnvPlaceholders(value.url);
    if (value.headers !== undefined) {
      entry.headers = stringRecord(value.headers, `mcpServers.${name}.headers`, path);
    }
    return entry;
  }
  if (typeof value.command !== "string" || value.command.trim() === "") {
    throw new Error(`Expected mcpServers.${name}.command in ${path} to be a non-empty string.`);
  }
  const args = value.args === undefined ? [] : value.args;
  if (!Array.isArray(args) || !args.every((arg) => typeof arg === "string")) {
    throw new Error(`Expected mcpServers.${name}.args in ${path} to be an array of strings.`);
  }
  entry.command = normalizeEnvPlaceholders(value.command);
  entry.args = args.map(normalizeEnvPlaceholders);
  if (typeof value.cwd === "string") {
    entry.cwd = value.cwd;
  }
  if (value.env !== undefined) {
    entry.env = stringRecord(value.env, `mcpServers.${name}.env`, path);
  }
  return entry;
}

function stringRecord(value: unknown, label: string, path: string): Record<string, string> {
  if (!isRecord(value) || !Object.values(value).every((item) => typeof item === "string")) {
    throw new Error(`Expected ${label} in ${path} to be an object of string values.`);
  }
  return Object.fromEntries(Object.entries(value as Record<string, string>).map(([key, item]) => [key, normalizeEnvPlaceholders(item)]));
}

// Legacy HTTP+SSE and WebSocket servers have no Streamable HTTP endpoint for Palizade to proxy.
function unsupportedTransport(value: unknown): string | undefined {
  const type = isRecord(value) ? value.type : undefined;
  return type === "sse" || type === "ws" ? type : undefined;
}

function makeAutoServerConfig(entry: ClientMcpServerEntry): JsonRecord {
  if (entry.url) {
    return {
      url: entry.url,
      headers: entry.headers ?? {},
      trust: "untrusted",
      toolClasses: {}
    };
  }
  return {
    command: entry.command,
    args: entry.args ?? [],
    ...(entry.cwd ? { cwd: entry.cwd } : {}),
    ...(entry.env ? { env: entry.env } : {}),
    trust: "untrusted",
    toolClasses: {}
  };
}

function makeLockApproveCommand(options: {
  nodePath: string;
  cliPath: string;
  palizadeConfigPath: string;
  serverName: string;
}): string {
  return [
    quoteShellArg(options.nodePath),
    quoteShellArg(resolve(options.cliPath)),
    "-c",
    quoteShellArg(options.palizadeConfigPath),
    "lock",
    "approve",
    quoteShellArg(options.serverName)
  ].join(" ");
}

function quoteShellArg(value: string): string {
  if (/^[A-Za-z0-9_./:\\-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll("\"", "\\\"")}"`;
}

function isLikelyPalizadeCliToken(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.includes("palizade") || lower.includes("palisade")) {
    return true;
  }
  const normalized = lower.replaceAll("\\", "/");
  return normalized.endsWith("/packages/cli/dist/index.cjs") ||
    normalized.endsWith("/packages/cli/dist/index.js") ||
    basename(lower) === "palizade" ||
    basename(lower) === "palizade.cmd" ||
    basename(lower) === "palizade.exe";
}

function isClaudeCodeClientPath(path: string): boolean {
  const lower = path.toLowerCase();
  return basename(lower) === ".claude.json" || lower.includes("\\.claude\\") || lower.includes("/.claude/");
}

function claudeCodeNativeToolsNote(): string {
  return "install-config wraps MCP servers only. Claude Code native tools (Bash, Read, Write, WebFetch) are covered only after palizade install-hooks claude-code.";
}

async function validatePalizadeConfig(path: string): Promise<string[]> {
  if (await exists(path)) {
    return [];
  }
  return [`Warning: Palizade config does not exist yet: ${path}`];
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
