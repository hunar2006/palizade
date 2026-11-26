import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { copyFile, lstat, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, platform as osPlatform } from "node:os";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep, win32 } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { loadConfig } from "@palizade/core";
import { getRunningCliPath } from "./install-config.js";

type JsonRecord = Record<string, unknown>;
const CLAUDE_PRE_TOOLS = ["Bash", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "mcp__.*"];
const CLAUDE_POST_TOOLS = [
  "Read", "WebFetch", "WebSearch", "Grep", "Glob", "Bash", "PowerShell", "Agent",
  "ReadMcpResourceTool", "ReadMcpResourceDirTool", "ListMcpResourcesTool", "mcp__.*"
];
const WINDOWS_POWERSHELL_PATH = /^[A-Z]:\\[A-Z0-9_.\\-]+\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/iu;
const LEGACY_WINDOWS_HOOK_LAUNCH = /^(?:[A-Z]:\\[A-Z0-9_.\\-]+\\System32\\WindowsPowerShell\\v1\.0\\)?powershell\.exe -NoProfile -NonInteractive -EncodedCommand (?=[\w+/=]+$)/iu;
const LEGACY_WINDOWS_HOOK_PREFIX = ` -NoProfile -NonInteractive -Command "Set-Variable LASTEXITCODE 2; & ([scriptblock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('`;
const WINDOWS_HOOK_PREFIX = LEGACY_WINDOWS_HOOK_PREFIX.replace('-Command "', '-Command "trap { exit 2 }; ');
const WINDOWS_HOOK_SUFFIX = `')))); [Environment]::Exit((Get-Variable LASTEXITCODE -ValueOnly))" ; exit $LASTEXITCODE`;
const WINDOWS_HOOK_SCRIPT = "& { param($node, $cli) $ProgressPreference = 'SilentlyContinue'; if (!(Test-Path -LiteralPath $node -PathType Leaf) -or !(Test-Path -LiteralPath $cli -PathType Leaf)) { exit 2 }; $global:LASTEXITCODE = $null; & $node $cli @args; if ($null -eq $LASTEXITCODE) { exit 2 }; exit $LASTEXITCODE } ";

export interface InstallHooksResult {
  client: string;
  settingsPath: string;
  existed: boolean;
  written: boolean;
  backupPath?: string;
  projectRoot?: string;
  configJson: string;
}

export function hookCommandParts(extraArgs: string[], nodePath: string = process.execPath, cliPath: string = getRunningCliPath()): string[] {
  return [nodePath, resolve(cliPath), ...extraArgs];
}

export async function installHooks(client: string, options: {
  configPath: string;
  settingsPath?: string;
  project?: boolean;
  dryRun?: boolean;
  cwd?: string;
}): Promise<InstallHooksResult> {
  const cwd = options.cwd ?? process.cwd();
  const gitRoot = findGitRoot(cwd);
  const projectRoot = client === "claude-code" && options.project && !options.settingsPath
    ? gitRoot ? mainCheckoutRoot(gitRoot) : resolve(cwd) : undefined;
  const settingsPath = options.settingsPath ? resolve(cwd, options.settingsPath) :
    projectRoot ? join(projectRoot, ".claude", "settings.local.json") : resolveHooksSettingsPath(client, undefined, undefined, options.project ? cwd : undefined);
  if (projectRoot && !gitRoot) {
    console.warn(`No git repository found. Using the current directory for Claude Code project hooks: ${cwd}`);
  }
  const absoluteConfigPath = resolve(cwd, options.configPath);
  const parts = installedHookParts(absoluteConfigPath, settingsPath);
  warnHookCliPath(parts[1]!, gitRoot ?? cwd, projectRoot);
  if (options.project) await checkSettingsPath(dirname(settingsPath), true);
  const existed = await checkSettingsPath(settingsPath, options.project);
  const settings = existed ? await readSettings(settingsPath) : {};
  const originalJson = existed ? `${JSON.stringify(settings, null, 2)}\n` : undefined;
  const timeoutMs = (client === "codex" || client === "gemini") && await exists(absoluteConfigPath)
    ? (await loadConfig(absoluteConfigPath)).hooks.timeoutMs : undefined;
  const merged = mergeHookEntries(client, settings, parts, absoluteConfigPath, timeoutMs);
  const configJson = `${JSON.stringify(merged, null, 2)}\n`;
  const result = { client, settingsPath, existed, configJson, ...(projectRoot ? { projectRoot } : {}) };

  if (options.dryRun || configJson === originalJson) {
    return { ...result, written: false };
  }

  await mkdir(dirname(settingsPath), { recursive: true });
  let backupPath: string | undefined;
  if (existed) {
    backupPath = `${settingsPath}.bak`;
    await checkSettingsPath(backupPath, options.project);
    await copyFile(settingsPath, backupPath);
  }
  await writeFile(settingsPath, configJson, "utf8");
  return { ...result, written: true, ...(backupPath ? { backupPath } : {}) };
}

export function mergeHookEntries(client: string, settings: JsonRecord, cliParts: string[], configPath: string, timeoutMs?: number): JsonRecord {
  const hookDefinition = buildHookDefinition(client, cliParts, timeoutMs);
  if (client === "cursor") {
    settings.version = settings.version ?? 1;
    const hooks = ensureRecord(settings, "hooks");
    for (const [event, definitions] of Object.entries(hookDefinition as Record<string, unknown>)) {
      for (const definition of definitions as unknown[]) {
        upsert(ensureArray(hooks, event), definition, isPalizadeHookCommand);
      }
    }
    return settings;
  }
  if (client === "claude-code" || client === "codex" || client === "gemini") {
    const hooks = ensureRecord(settings, "hooks");
    for (const [event, group] of Object.entries(hookDefinition)) {
      upsertGroup(ensureArray(hooks, event), group);
    }
    return settings;
  }
  throw new Error(`Unsupported hook client '${client}'. Supported: claude-code, cursor, codex, gemini.`);
}

export interface HookCoverage {
  settingsPath: string;
  exists: boolean;
  /** Each event Palizade installs, and whether its entry is there and current. */
  events: Array<{ event: string; status: "installed" | "outdated" | "missing"; observedAt?: string }>;
}

interface HookObservationScope { configPath: string; stateDir: string; timeoutMs: number }

/** Reports which Palizade hook entries a client's settings file has; "outdated" means install-hooks would change it. */
export async function inspectHooks(client: string, settingsPath = resolveHooksSettingsPath(client), scope?: HookObservationScope): Promise<HookCoverage> {
  if (!await exists(settingsPath)) return { settingsPath, exists: false, events: Object.keys(buildHookDefinition(client, ["node", "palizade", "hook"])).map((event) => ({ event, status: "missing" as const })) };
  const settings = await readSettings(settingsPath);
  const hooks = isRecord(settings.hooks) ? settings.hooks : {};
  const expected = buildHookDefinition(client, scope ? installedHookParts(scope.configPath, settingsPath) : ["node", "palizade", "hook"], scope?.timeoutMs);
  // Compare everything but the command and paths, which differ per machine.
  const shape = (value: unknown): unknown => JSON.parse(JSON.stringify(value, (key, field) => {
    if (key === "command" || key === "args") return undefined;
    const minimum = client === "gemini" ? 45_000 : 45;
    return key === "timeout" && Number.isInteger(field) && field >= minimum ? minimum : field;
  }));
  const events = await Promise.all(Object.entries(expected).map(async ([event, definition]) => {
    const registrations = palizadeRegistrations(client, hooks, event);
    if (registrations.length === 0) return { event, status: "missing" as const };
    if (registrations.length !== 1) return { event, status: "outdated" as const };
    const [ours] = registrations;
    const wanted = client === "cursor" ? (definition as unknown[])[0] : definition;
    if (scope) {
      if (!isDeepStrictEqual(ours, wanted)) return { event, status: "outdated" as const };
      const observedAt = await readHookObservation(markerPath(scope, client, settingsPath, event, wanted));
      return { event, status: "installed" as const, ...(observedAt ? { observedAt } : {}) };
    }
    const promptArgsOk = client === "cursor" || !event.includes("Prompt") || (groupContainsPalizade(ours) &&
      ours.hooks.some((hook) => isRecord(hook) && isPalizadeHookCommand(hook) && hookCommandTokens(hook).includes(event)));
    const cursorCommandOk = client !== "cursor" || process.platform !== "win32" ||
      (isRecord(ours) && typeof ours.command === "string" && decodeWindowsHookCommand(ours.command, false)?.startsWith(WINDOWS_HOOK_SCRIPT));
    const codexCommandOk = client !== "codex" || (groupContainsPalizade(ours) &&
      !ours.hooks.some((hook) => isRecord(hook) && isPalizadeHookCommand(hook) && Array.isArray(hook.args)));
    const groupCommandOk = process.platform !== "win32" || (client !== "gemini" && client !== "codex") ||
      (groupContainsPalizade(ours) && ours.hooks.some((hook) => isRecord(hook) && typeof hook.command === "string" &&
        decodeWindowsHookCommand(hook.command, false)?.startsWith(WINDOWS_HOOK_SCRIPT)));
    return { event, status: JSON.stringify(shape(ours)) === JSON.stringify(shape(wanted)) && promptArgsOk && cursorCommandOk && codexCommandOk && groupCommandOk ? "installed" as const : "outdated" as const };
  }));
  return { settingsPath, exists: true, events };
}

export function resolveHooksSettingsPath(client: string, platform: string = osPlatform(), homeDir: string = homedir(), projectDir?: string, env = process.env): string {
  const join = platform === "win32" ? win32.join : posix.join;
  if (client === "claude-code") {
    const gitRoot = projectDir && platform === osPlatform() ? findGitRoot(projectDir) : undefined;
    const root = gitRoot ? mainCheckoutRoot(gitRoot) : projectDir;
    return root ? join(root, ".claude", "settings.local.json") : join(env.CLAUDE_CONFIG_DIR || join(homeDir, ".claude"), "settings.json");
  }
  if (client === "cursor") {
    return join(projectDir ?? homeDir, ".cursor", "hooks.json");
  }
  if (client === "codex") {
    return projectDir ? join(projectDir, ".codex", "hooks.json") : join(env.CODEX_HOME || join(homeDir, ".codex"), "hooks.json");
  }
  if (client === "gemini") {
    return join(projectDir ?? homeDir, ".gemini", "settings.json");
  }
  throw new Error(`Unsupported hook client '${client}'. Supported: claude-code, cursor, codex, gemini.`);
}

function findGitRoot(cwd: string): string | undefined {
  for (let dir = resolve(cwd); ; dir = dirname(dir)) {
    if (existsSync(join(dir, ".git"))) return dir;
    if (dirname(dir) === dir) return undefined;
  }
}

function mainCheckoutRoot(worktree: string): string {
  const gitfile = join(worktree, ".git");
  try {
    if (!lstatSync(gitfile).isFile()) return worktree;
    const target = /^gitdir: (.+)$/u.exec(readFileSync(gitfile, "utf8").trim())?.[1];
    if (!target) return worktree;
    const gitDir = resolve(worktree, target);
    const common = readFileSync(join(gitDir, "commondir"), "utf8").trim();
    const commonDir = resolve(gitDir, common);
    const backlink = readFileSync(join(gitDir, "gitdir"), "utf8").trim();
    if (common && basename(commonDir) === ".git" && relative(dirname(gitDir), join(commonDir, "worktrees")) === "" &&
        relative(resolve(gitDir, backlink), gitfile) === "" && lstatSync(commonDir).isDirectory()) return dirname(commonDir);
  } catch {
    // Incomplete worktree metadata falls back to the worktree itself.
  }
  return worktree;
}

async function checkSettingsPath(path: string, project = false): Promise<boolean> {
  try {
    const info = await (project ? lstat(path) : stat(path));
    if (info.isSymbolicLink()) throw new Error(`Refusing to use symlinked project hook settings path: ${path}`);
    if (info.isFile() && info.nlink > 1) throw new Error(`Refusing to use hard-linked hook settings file: ${path}`);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function warnHookCliPath(cliPath: string, workspace: string, projectRoot?: string): void {
  const real = (path: string) => { try { return realpathSync(path); } catch { return resolve(path); } };
  const target = real(cliPath);
  const inside = (root: string) => [relative(root, cliPath), relative(real(root), target)]
    .some((path) => !isAbsolute(path) && path.split(sep)[0] !== "..");
  const cacheRoots = [process.env.npm_config_cache || process.env.NPM_CONFIG_CACHE, join(homedir(), ".npm"),
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "npm-cache")];
  const cachePaths = [cliPath, target].map((path) => path.replaceAll("\\", "/"));
  const cache = cachePaths.some((path) => /\/(?:_npx|_cacache|npm-cache)\//iu.test(path)) || cacheRoots.some((root) => root && inside(resolve(root))) ? "an npm cache" :
    cachePaths.some((path) => /\/(?:pnpm(?:-cache)?\/dlx|dlx\/[^/]+\/pkg\/node_modules)\//iu.test(path)) ? "a pnpm dlx cache" :
    cachePaths.some((path) => /\/(?:xfs-[\da-f]+\/dlx-\d+|\.yarn\/(?:berry\/)?cache)\//iu.test(path)) ? "a Yarn dlx cache" :
    cachePaths.some((path) => /\/\.?bunx-[^/]+\//iu.test(path)) ? "a bunx cache" : undefined;
  if (cache || inside(workspace) || (projectRoot && inside(projectRoot))) {
    console.warn(`Warning: hooks will run a Palizade CLI inside ${cache ?? "the workspace"}: ${cliPath}. A global install avoids depending on files here.`);
  }
}

/** Stores diagnostic evidence only for a successful evaluation from the current installation. */
export async function observeHook(scope: HookObservationScope, client: string, settingsPath: string, event: string): Promise<void> {
  try {
    const settings = await readSettings(settingsPath);
    if (!isRecord(settings.hooks)) return;
    const definition = buildHookDefinition(client, installedHookParts(scope.configPath, settingsPath), scope.timeoutMs)[event];
    const wanted = client === "cursor" && Array.isArray(definition) ? definition[0] : definition;
    if (wanted === undefined || !isDeepStrictEqual(palizadeRegistrations(client, settings.hooks, event), [wanted])) return;
    const path = markerPath(scope, client, settingsPath, event, wanted);
    if (await exists(path)) return;
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, `${new Date().toISOString()}\n`, { flag: "wx", mode: 0o600 });
  } catch {
    // A diagnostics I/O failure must never affect a hook decision.
  }
}

function installedHookParts(configPath: string, settingsPath: string): string[] {
  return hookCommandParts(["-c", resolve(configPath), "hook", "--hook-source", resolve(settingsPath)]);
}

function palizadeRegistrations(client: string, hooks: JsonRecord, event: string): unknown[] {
  const list = hooks[event];
  return Array.isArray(list) ? list.filter(client === "cursor" ? isPalizadeHookCommand : groupContainsPalizade) : [];
}

function markerPath(scope: HookObservationScope, client: string, settingsPath: string, event: string, registration: unknown): string {
  const key = createHash("sha256").update(JSON.stringify([client, resolve(scope.configPath), resolve(settingsPath), event, registration])).digest("hex");
  return join(scope.stateDir, "hook-observations", key);
}

async function readHookObservation(path: string): Promise<string | undefined> {
  try {
    const value = (await readFile(path, "utf8")).trim();
    return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function buildHookDefinition(client: string, cliParts: string[], timeoutMs = 30_000): JsonRecord {
  if (client === "claude-code") {
    const command = cliParts[0]!;
    const args = [...cliParts.slice(1), "claude-code"];
    return {
      // onFailure: block makes a crashed or missing hook deny the call (Claude Code 2.1.295+).
      // mcp__.* covers MCP servers that are not wrapped, such as remote servers that sign in with OAuth.
      PreToolUse: {
        matcher: `^(${CLAUDE_PRE_TOOLS.join("|")})$`,
        hooks: [{ type: "command", command, args, onFailure: "block" }]
      },
      PostToolUse: {
        matcher: `^(${CLAUDE_POST_TOOLS.join("|")})$`,
        hooks: [{ type: "command", command, args }]
      },
      // Remembers destinations the user typed; never blocks the prompt.
      UserPromptSubmit: {
        hooks: [{ type: "command", command, args: [...args, "UserPromptSubmit"] }]
      }
    };
  }
  if (client === "cursor") {
    const command = (...args: string[]) => portableHookCommand([...cliParts, "cursor", ...args]);
    return {
      beforeShellExecution: [{ command: command(), failClosed: true }],
      beforeMCPExecution: [{ command: command(), failClosed: true }],
      afterShellExecution: [{ command: command() }],
      afterMCPExecution: [{ command: command() }],
      beforeSubmitPrompt: [{ command: command("beforeSubmitPrompt") }]
    };
  }
  const timeoutSeconds = Math.max(45, Math.ceil((timeoutMs + 15_000) / 1000));
  if (client === "gemini") {
    // Gemini runs `command` through a shell; it has no args field. Timeouts are in milliseconds.
    const line = (event: string) => portableHookCommand([...cliParts, "gemini", event]);
    return {
      BeforeTool: { matcher: "run_shell_command|write_file|replace|web_fetch|mcp_.*", hooks: [{ type: "command", name: "palizade", command: line("BeforeTool"), timeout: timeoutSeconds * 1000 }] },
      AfterTool: { matcher: "read_file|read_many_files|web_fetch|grep_search|glob|list_directory|google_web_search|run_shell_command|mcp_.*", hooks: [{ type: "command", name: "palizade", command: line("AfterTool"), timeout: timeoutSeconds * 1000 }] },
      BeforeAgent: { hooks: [{ type: "command", name: "palizade", command: line("BeforeAgent"), timeout: timeoutSeconds * 1000 }] }
    };
  }
  const command = (...args: string[]) => portableHookCommand([...cliParts, "codex", ...args]);
  return {
    PreToolUse: {
      matcher: "Bash|apply_patch|mcp__.*",
      hooks: [{ type: "command", command: command(), timeout: timeoutSeconds }]
    },
    PostToolUse: {
      matcher: "Read|WebFetch|Grep|Glob|Bash|mcp__.*",
      hooks: [{ type: "command", command: command(), timeout: timeoutSeconds }]
    },
    UserPromptSubmit: {
      hooks: [{ type: "command", command: command("UserPromptSubmit"), timeout: timeoutSeconds }]
    }
  };
}

// Re-running install-hooks updates an older Palizade entry in place instead of adding a second one.
function upsert(list: unknown[], entry: unknown, isOurs: (item: unknown) => boolean): void {
  const index = list.findIndex(isOurs);
  if (index === -1) list.push(entry);
  else {
    for (let i = list.length - 1; i > index; i -= 1) {
      if (isOurs(list[i])) list.splice(i, 1);
    }
    list[index] = entry;
  }
}

function upsertGroup(list: unknown[], entry: unknown): void {
  const index = list.findIndex(groupContainsPalizade);
  if (index === -1) {
    list.push(entry);
    return;
  }
  for (let i = list.length - 1; i >= index; i -= 1) {
    const group = list[i];
    if (!groupContainsPalizade(group)) continue;
    const otherHooks = group.hooks.filter((hook) => !isPalizadeHookCommand(hook));
    list.splice(i, 1, ...(otherHooks.length > 0 ? [{ ...group, hooks: otherHooks }] : []), ...(i === index ? [entry] : []));
  }
}

function portableHookCommand(parts: string[]): string {
  if (process.platform !== "win32") return parts.map(quotePosixArg).join(" ");
  // cmd passes the final exit to -Command; a PowerShell parent runs it to preserve the child status.
  const root = process.env.SystemRoot || "C:\\Windows";
  if (!/^[A-Z]:\\[A-Z0-9_.\\-]+$/iu.test(root) || root.split("\\").includes("..")) throw new Error("SystemRoot cannot be used as an absolute Windows hook executable path.");
  const launcher = win32.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  if (!statSync(launcher, { throwIfNoEntry: false })?.isFile()) throw new Error(`Windows hook launcher not found: ${launcher}`);
  return launcher + WINDOWS_HOOK_PREFIX + Buffer.from(powerShellCommand(parts), "utf16le").toString("base64") + WINDOWS_HOOK_SUFFIX;
}

function powerShellCommand(parts: string[]): string {
  const quote = (value: string) => `'${value.replace(/['\u2018-\u201B]/gu, "$&$&")}'`;
  return `${WINDOWS_HOOK_SCRIPT}${parts.map(quote).join(" ")}; if ($null -eq $LASTEXITCODE) { exit 2 }; exit $LASTEXITCODE`;
}

function quotePosixArg(value: string): string {
  return /^[A-Za-z0-9_./:-]+$/u.test(value) ? value : `"${value.replace(/[\\"$`]/gu, "\\$&")}"`;
}

function groupContainsPalizade(group: unknown): group is JsonRecord & { hooks: unknown[] } {
  return isRecord(group) && Array.isArray(group.hooks) && group.hooks.some(isPalizadeHookCommand);
}

function isPalizadeHookCommand(hook: unknown): boolean {
  if (!isRecord(hook)) {
    return false;
  }
  const tokens = hookCommandTokens(hook);
  if (!tokens.includes("hook")) return false;
  return tokens.slice(0, 2).some((token) => {
    if (typeof token !== "string") return false;
    const path = token.replaceAll("\\", "/");
    return /(?:^|\/)(?:palizade(?:\.(?:cmd|exe))?|(?:palizade|packages\/cli)\/dist\/index\.(?:cjs|js))$/iu.test(path);
  });
}

function hookCommandTokens(hook: JsonRecord): unknown[] {
  // Older Codex installs and current Claude Code hooks store argv separately.
  let command = typeof hook.command === "string" ? hook.command : "";
  command = decodeWindowsHookCommand(command) ?? command;
  if (command.startsWith(WINDOWS_HOOK_SCRIPT)) command = command.slice(WINDOWS_HOOK_SCRIPT.length);
  return Array.isArray(hook.args) ? [command, ...hook.args] :
    (command.trimStart().replace(/^&\s+/u, "").match(/"(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\s"';]+/gu) ?? []).map((token) => token.replace(/^["']|["']$/gu, ""));
}

function decodeWindowsHookCommand(command: string, allowLegacy = true): string | undefined {
  const launcher = command.match(WINDOWS_POWERSHELL_PATH)?.[0] ?? "";
  const prefixes = allowLegacy ? [WINDOWS_HOOK_PREFIX, LEGACY_WINDOWS_HOOK_PREFIX] : [WINDOWS_HOOK_PREFIX];
  const prefix = launcher && prefixes.find((candidate) => command.startsWith(launcher + candidate));
  if (prefix && command.endsWith(WINDOWS_HOOK_SUFFIX)) {
    const encoded = command.slice(launcher.length + prefix.length, -WINDOWS_HOOK_SUFFIX.length);
    return /^[\w+/=]+$/u.test(encoded) ? Buffer.from(encoded, "base64").toString("utf16le") : undefined;
  }
  const legacy = allowLegacy ? command.match(LEGACY_WINDOWS_HOOK_LAUNCH)?.[0] : undefined;
  return legacy && Buffer.from(command.slice(legacy.length), "base64").toString("utf16le");
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
