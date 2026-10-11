import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, platform as osPlatform } from "node:os";
import { dirname, posix, resolve, win32 } from "node:path";
import { getRunningCliPath } from "./install-config.js";

type JsonRecord = Record<string, unknown>;

export interface InstallHooksResult {
  client: string;
  settingsPath: string;
  existed: boolean;
  written: boolean;
  backupPath?: string;
  configJson: string;
}

export function hookCommandParts(extraArgs: string[], nodePath: string = process.execPath, cliPath: string = getRunningCliPath()): string[] {
  return [nodePath, resolve(cliPath), ...extraArgs];
}

export async function installHooks(client: string, options: {
  configPath: string;
  settingsPath?: string;
  dryRun?: boolean;
  cwd?: string;
}): Promise<InstallHooksResult> {
  const cwd = options.cwd ?? process.cwd();
  const settingsPath = options.settingsPath ? resolve(cwd, options.settingsPath) : resolveHooksSettingsPath(client);
  const absoluteConfigPath = resolve(cwd, options.configPath);
  const parts = hookCommandParts(["-c", absoluteConfigPath, "hook"]);
  const existed = await exists(settingsPath);
  const settings = existed ? await readSettings(settingsPath) : {};
  const merged = mergeHookEntries(client, settings, parts, absoluteConfigPath);
  const configJson = `${JSON.stringify(merged, null, 2)}\n`;

  if (options.dryRun) {
    return { client, settingsPath, existed, written: false, configJson };
  }

  await mkdir(dirname(settingsPath), { recursive: true });
  let backupPath: string | undefined;
  if (existed) {
    backupPath = `${settingsPath}.bak`;
    await copyFile(settingsPath, backupPath);
  }
  await writeFile(settingsPath, configJson, "utf8");
  return { client, settingsPath, existed, written: true, configJson, ...(backupPath ? { backupPath } : {}) };
}

export function mergeHookEntries(client: string, settings: JsonRecord, cliParts: string[], configPath: string): JsonRecord {
  const hookDefinition = buildHookDefinition(client, cliParts);
  if (client === "claude-code") {
    const hooks = ensureRecord(settings, "hooks");
    for (const [event, groups] of Object.entries(hookDefinition as Record<string, unknown>)) {
      const list = ensureArray(hooks, event);
      if (!list.some((group) => groupContainsPalizade(group))) {
        list.push(groups);
      }
    }
    return settings;
  }
  if (client === "cursor") {
    settings.version = settings.version ?? 1;
    const hooks = ensureRecord(settings, "hooks");
    for (const [event, definitions] of Object.entries(hookDefinition as Record<string, unknown>)) {
      const list = ensureArray(hooks, event);
      const defs = definitions as unknown[];
      for (const definition of defs) {
        if (!list.some((item) => typeof item === "object" && item !== null && isPalizadeHookCommand(item))) {
          list.push(definition);
        }
      }
    }
    return settings;
  }
  if (client === "codex") {
    const hooks = ensureRecord(settings, "hooks");
    for (const [event, groups] of Object.entries(hookDefinition as Record<string, unknown>)) {
      const list = ensureArray(hooks, event);
      if (!list.some((group) => groupContainsPalizade(group))) {
        list.push(groups);
      }
    }
    return settings;
  }
  throw new Error(`Unsupported hook client '${client}'. Supported: claude-code, cursor, codex.`);
}

export function resolveHooksSettingsPath(client: string, platform: string = osPlatform(), homeDir: string = homedir()): string {
  if (client === "claude-code") {
    return posix.join(homeDir, ".claude", "settings.json");
  }
  if (client === "cursor") {
    return posix.join(homeDir, ".cursor", "hooks.json");
  }
  if (client === "codex") {
    return posix.join(homeDir, ".codex", "hooks.json");
  }
  throw new Error(`Unsupported hook client '${client}'. Supported: claude-code, cursor, codex.`);
}

function buildHookDefinition(client: string, cliParts: string[]): JsonRecord {
  if (client === "claude-code") {
    const command = cliParts[0]!;
    const args = [...cliParts.slice(1), "claude-code"];
    return {
      PreToolUse: {
        matcher: "Bash|Write|Edit|WebFetch",
        hooks: [{ type: "command", command, args }]
      },
      PostToolUse: {
        matcher: "Read|WebFetch|Grep|Glob",
        hooks: [{ type: "command", command, args }]
      }
    };
  }
  if (client === "cursor") {
    const commandLine = [...cliParts, "cursor"].map(quoteShellArg).join(" ");
    return {
      beforeShellExecution: [{ command: commandLine, failClosed: true }],
      beforeMCPExecution: [{ command: commandLine, failClosed: true }],
      afterShellExecution: [{ command: commandLine }],
      afterMCPExecution: [{ command: commandLine }]
    };
  }
  const command = cliParts[0]!;
  const args = [...cliParts.slice(1), "codex"];
  return {
    PreToolUse: {
      matcher: "Bash|apply_patch|mcp__.*",
      hooks: [{ type: "command", command, args, timeout: 30 }]
    },
    PostToolUse: {
      matcher: "Read|WebFetch|Grep|Glob|mcp__.*",
      hooks: [{ type: "command", command, args, timeout: 30 }]
    }
  };
}

function quoteShellArg(value: string): string {
  if (/^[A-Za-z0-9_./:\\-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll("\"", "\\\"")}"`;
}

function groupContainsPalizade(group: unknown): boolean {
  if (!isRecord(group)) {
    return false;
  }
  const hookList = Array.isArray(group.hooks) ? group.hooks : [];
  return hookList.some((hook) => isRecord(hook) && (isPalizadeHookCommand(hook) || (Array.isArray(hook.args) && hook.args.includes("hook"))));
}

function isPalizadeHookCommand(hook: unknown): boolean {
  if (!isRecord(hook)) {
    return false;
  }
  const tokens = [typeof hook.command === "string" ? hook.command : "", ...(Array.isArray(hook.args) ? hook.args.map(String) : [])];
  return tokens.some((token) => token.toLowerCase().includes("palizade")) && tokens.includes("hook");
}

function ensureRecord(parent: JsonRecord, key: string): JsonRecord {
  const existing = parent[key];
  if (existing === undefined) {
    const record: JsonRecord = {};
    parent[key] = record;
    return record;
  }
  if (!isRecord(existing)) {
    throw new Error(`Expected ${key} to be an object. Refusing to overwrite malformed settings.`);
  }
  return existing;
}

function ensureArray(parent: JsonRecord, key: string): unknown[] {
  const existing = parent[key];
  if (existing === undefined) {
    const list: unknown[] = [];
    parent[key] = list;
    return list;
  }
  if (!Array.isArray(existing)) {
    throw new Error(`Expected ${key} to be an array. Refusing to overwrite malformed settings.`);
  }
  return existing;
}

async function readSettings(path: string): Promise<JsonRecord> {
  const raw = await readFile(path, "utf8");
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) {
      throw new Error("top-level JSON value must be an object");
    }
    return parsed;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse settings at ${path}: ${reason}. Refusing to overwrite it.`);
  }
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
