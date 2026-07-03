import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, platform as osPlatform } from "node:os";
import { dirname, posix, resolve, win32 } from "node:path";

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
  entryName?: string | undefined;
  dryRun?: boolean | undefined;
  force?: boolean | undefined;
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
  command: string;
  args: string[];
}

export async function installClientConfig(options: InstallConfigOptions): Promise<InstallConfigResult> {
  const client = options.client ?? "claude-desktop";
  const cwd = options.cwd ?? process.cwd();
  const clientConfigPath = options.clientConfigPath
    ? resolve(cwd, options.clientConfigPath)
    : resolveClientConfigPath(client);
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
  const mcpServers = ensureMcpServers(config, clientConfigPath);
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

export function selectInstallConfigPath(commandOptions: OptionValueReader, rootOptions: OptionValueReader): string | undefined {
  return cliOptionValue(commandOptions, "config") ?? cliOptionValue(rootOptions, "config");
}

export function resolvePalizadeConfigPath(configPath: string | undefined, cwd = process.cwd()): string {
  return resolve(cwd, configPath ?? "./palizade.yaml");
}

export function resolveClientConfigPath(client: string, platform = osPlatform(), env: NodeJS.ProcessEnv = process.env, homeDir = homedir()): string {
  if (client !== "claude-desktop") {
    throw new Error(`Unsupported client '${client}'. Supported clients: claude-desktop.`);
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

function cliOptionValue(options: OptionValueReader, name: string): string | undefined {
  const source = options.getOptionValueSource(name);
  if (!source || source === "default") {
    return undefined;
  }
  const value = options.getOptionValue(name);
  return typeof value === "string" ? value : undefined;
}

export function getRunningCliPath(argv1 = process.argv[1]): string {
  if (argv1 && argv1.trim() !== "") {
    return resolve(argv1);
  }
  throw new Error("Unable to determine the running Palizade CLI path.");
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
    throw new Error(`Failed to parse Claude Desktop config at ${path}: ${reason}. Refusing to overwrite it.`);
  }
}

function ensureMcpServers(config: JsonRecord, path: string): JsonRecord {
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
