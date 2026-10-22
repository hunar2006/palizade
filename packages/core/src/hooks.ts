import { StaticApprovalProvider } from "@palizade/approvals";
import { AuditLogger, JsonlAuditSink, SqliteAuditSink, type AuditEvent } from "@palizade/audit";
import { loadPolicyFile } from "@palizade/policy";
import { SqliteTaintStore, extractStatedObservables } from "@palizade/taint";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";
import { createDetector } from "./factory.js";
import { serverConfigSchema, type PalizadeConfig, type ServerConfig } from "./config.js";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { JsonRpcMessage } from "./mcp.js";

export type NativeClient = "claude-code" | "cursor" | "codex";

export interface HookDecisionOutput {
  exitCode: 0 | 2;
  output: unknown;
  reason: string;
}

export interface HookEngineContext {
  engine: InterceptionEngine;
  events: AuditEvent[];
  close: () => void;
}

const HOOK_SERVER: Omit<ServerConfig, "cwd"> & { cwd?: string } = {
  // shortcut: native hooks have no tools/list metadata lock, extend native capability mapping when supported clients add tool types.
  command: "native-tools",
  args: [],
  env: {},
  headers: {},
  protocolVersion: "auto",
  trust: "untrusted",
  toolClasses: {
    Bash: "sink",
    Shell: "sink",
    shell: "sink",
    Write: "sink",
    Edit: "sink",
    apply_patch: "sink",
    WebFetch: "sink",
    Read: "source",
    Grep: "source",
    Glob: "source"
  },
  toolCapabilities: {
    Bash: ["executes_code", "network_egress", "writes_local"],
    Shell: ["executes_code", "network_egress", "writes_local"],
    shell: ["executes_code", "network_egress", "writes_local"],
    Write: ["file_write", "writes_local"],
    Edit: ["file_write", "writes_local"],
    apply_patch: ["file_write", "writes_local"],
    WebFetch: ["network_egress", "reads_untrusted_content"]
  },
  argumentRoles: {
    Bash: { command: "shell_command", urls: "url", hosts: "hostname", redirectTargets: "file_path" },
    Shell: { command: "shell_command", urls: "url", hosts: "hostname", redirectTargets: "file_path" },
    shell: { command: "shell_command", urls: "url", hosts: "hostname", redirectTargets: "file_path" },
    Write: { file_path: "file_path", content: "body" },
    Edit: { file_path: "file_path", old_string: "body", new_string: "body" },
    apply_patch: { file_path: "file_path", patch: "body" },
    WebFetch: { url: "url" }
  },
  sensitive: false,
  sensitiveTools: {},
  sensitivePathPatterns: [],
  shell: false,
  allowShell: false
};

export async function createHookEngine(
  config: PalizadeConfig,
  sessionId: string,
  cwd: string,
  capture: AuditEvent[] = [],
  target: { serverName: string; server: ServerConfig } = { serverName: "native-tools", server: { ...HOOK_SERVER, cwd } }
): Promise<HookEngineContext> {
  // shortcut: each one-shot hook opens a fresh engine/store, use a persistent daemon if hook startup latency or shared split windows are required.
  const server = target.server;
  const policy = await loadPolicyFile(config.policy);
  const taintStore = new SqliteTaintStore(config.taint.sqlite, {
    scope: config.taint.scope,
    profileId: config.taint.profileId,
    keyPath: config.taint.keyPath,
    ttlMs: config.taint.ttlMs,
    sessionScope: "client",
    ...(process.env.PALIZADE_RUN_ID ? { runId: process.env.PALIZADE_RUN_ID } : {})
  });
  const captureSink = {
    write: async (event: AuditEvent): Promise<void> => {
      capture.push(event);
    }
  };
  const audit = new AuditLogger([
    new JsonlAuditSink(config.audit.jsonl),
    new SqliteAuditSink(config.audit.sqlite),
    captureSink
  ], { captureRawPayloads: config.audit.captureRawPayloads });
  const engine = new InterceptionEngine({
    config,
    serverName: target.serverName,
    server,
    sessionId,
    policy,
    detector: createDetector(config),
    taintStore,
    audit,
    approvals: new StaticApprovalProvider(false, "native hooks defer approval decisions to the client"),
    lockfile: new LockfileStore(config.lockfile)
  });
  return {
    engine,
    events: capture,
    close: () => {
      taintStore.close();
      void audit.close();
    }
  };
}

export interface ShellAnalysis {
  commandName: string | undefined;
  urls: string[];
  hosts: string[];
  redirectTargets: string[];
  suspicious: string[];
}

const URL_RE = /\bhttps?:\/\/[^\s<>"')\]]+/giu;
const COMMAND_FLAGS_WITH_HOST = /\b(?:curl|wget|nc|ncat|scp|ssh|rsync|git\s+clone|ftp|sftp|ping|nslookup|dig|telnet|open)\b/iu;
const SUSPICIOUS_RE = /\$\([^)]*\)|`[^`]+`|\beval\b|\bbase64\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\bperl\s+-e\b|\/dev\/tcp\b|\bchmod\s+[0-7]*[45][0-7]*\b|\bcurl\b[^|;]*\|\s*(?:bash|sh|zsh)\b|\bwget\b[^|;]*\|\s*(?:bash|sh|zsh)\b/iu;
const BASE64ISH_RE = /\b[A-Za-z0-9+/]{40,}={0,2}\b/u;

export function analyzeShellCommand(command: string): ShellAnalysis {
  // shortcut: heuristic shell extraction misses complex quoting and indirect destinations, use a shell parser if supported command forms require it.
  const tokens = command.split(/\s*[;|&]\s*/u);
  const commandName = tokens[0]?.split(/\s+/u)[0]?.trim() || undefined;
  const urls = [...new Set(command.match(URL_RE) ?? [])];
  const hosts: string[] = [];
  const redirectTargets: string[] = [];
  for (const token of tokens) {
    const words = token.split(/\s+/u).filter(Boolean);
    if (words.length >= 2 && COMMAND_FLAGS_WITH_HOST.test(words[0] ?? "")) {
      for (const word of words.slice(1)) {
        if (word.startsWith("-")) {
          continue;
        }
        const candidate = word.replace(/^["']|["']$/gu, "");
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/iu.test(candidate) || /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u.test(candidate)) {
          hosts.push(candidate);
        }
      }
    }
    const redirect = /(?:^|\s)([12]?>>?|<)\s*([^\s]+)/gu.exec(token);
    if (redirect?.[2]) {
      redirectTargets.push(redirect[2].replace(/^["']|["']$/gu, ""));
    }
  }
  const suspicious = [...new Set([
    ...(SUSPICIOUS_RE.test(command) ? ["shell-suspicious-construct"] : []),
    ...(BASE64ISH_RE.test(command) ? ["encoded-payload"] : [])
  ])];
  return {
    commandName,
    urls: [...new Set(urls)],
    hosts: [...new Set(hosts)],
    redirectTargets: [...new Set(redirectTargets)],
    suspicious
  };
}

export interface NormalizedNativeEvent {
  kind: "pre" | "post";
  tool: string;
  input: Record<string, unknown>;
  response?: unknown;
}

export function normalizeNativeEvent(client: NativeClient, event: string, payload: unknown): NormalizedNativeEvent | undefined {
  const record = payload && typeof payload === "object" ? payload as Record<string, unknown> : {};
  const toolInput = record.tool_input;

  if (client === "claude-code") {
    if (event === "PreToolUse") {
      return { kind: "pre", tool: String(record.tool_name ?? "unknown"), input: normalizeToolInput(toolInput) };
    }
    if (event === "PostToolUse") {
      return { kind: "post", tool: String(record.tool_name ?? "unknown"), input: normalizeToolInput(toolInput), response: record.tool_response };
    }
    return undefined;
  }

  if (client === "cursor") {
    if (event === "beforeShellExecution" || event === "afterShellExecution") {
      return {
        kind: event === "beforeShellExecution" ? "pre" : "post",
        tool: "Shell",
        input: { command: String(record.command ?? "") },
        response: typeof record.output === "string" ? { content: [{ type: "text", text: record.output }] } : undefined
      };
    }
    if (event === "beforeMCPExecution" || event === "afterMCPExecution") {
      const toolName = String(record.tool_name ?? "unknown");
      let input: Record<string, unknown> = {};
      if (typeof record.tool_input === "string") {
        try {
          input = JSON.parse(record.tool_input) as Record<string, unknown>;
        } catch {
          input = { raw: record.tool_input };
        }
      }
      let response: unknown;
      if (typeof record.result_json === "string") {
        try {
          response = JSON.parse(record.result_json);
        } catch {
          response = { content: [{ type: "text", text: record.result_json }] };
        }
      }
      return { kind: event === "beforeMCPExecution" ? "pre" : "post", tool: toolName, input, response };
    }
    return undefined;
  }

  if (client === "codex") {
    if (event === "PreToolUse") {
      return { kind: "pre", tool: String(record.tool_name ?? "unknown"), input: normalizeToolInput(toolInput) };
    }
    if (event === "PostToolUse") {
      return { kind: "post", tool: String(record.tool_name ?? "unknown"), input: normalizeToolInput(toolInput), response: record.tool_response };
    }
    return undefined;
  }

  return undefined;
}

/** `mcp__<server>__<tool>`, the name Claude Code and Codex give MCP tools in hooks. */
export function parseMcpToolName(tool: string): { server: string; tool: string } | undefined {
  const match = /^mcp__(.+?)__(.+)$/u.exec(tool);
  return match ? { server: match[1]!, tool: match[2]! } : undefined;
}

type ClientServerEntry = { command?: string; args?: string[]; url?: string };

/**
 * Finds how the client itself launches an MCP server (command or url), so the tool catalog can
 * recognize it. Claude Code: ~/.claude.json (user and local scope) and .mcp.json in the project.
 */
export function findClientServerEntry(serverName: string, cwd: string, home = homedir()): ClientServerEntry | undefined {
  const read = (path: string): Record<string, unknown> | undefined => {
    try { return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown> : undefined; } catch { return undefined; }
  };
  const pick = (servers: unknown): ClientServerEntry | undefined => {
    const entry = servers && typeof servers === "object" ? (servers as Record<string, unknown>)[serverName] : undefined;
    if (!entry || typeof entry !== "object") return undefined;
    const record = entry as Record<string, unknown>;
    return {
      ...(typeof record.command === "string" ? { command: record.command } : {}),
      ...(Array.isArray(record.args) ? { args: record.args.filter((arg): arg is string => typeof arg === "string") } : {}),
      ...(typeof record.url === "string" ? { url: record.url } : {})
    };
  };
  const user = read(join(home, ".claude.json"));
  const projects = user?.projects && typeof user.projects === "object" ? user.projects as Record<string, { mcpServers?: unknown }> : {};
  return pick(read(join(cwd, ".mcp.json"))?.mcpServers) ?? pick(projects[cwd]?.mcpServers) ?? pick(user?.mcpServers);
}

/**
 * The Cursor config key of the MCP server a beforeMCPExecution/afterMCPExecution payload is for.
 * Cursor currently sends that key in `command` (and no url); if it sends the real command line or
 * url instead, the entry with that command or url is used.
 */
export function cursorServerKey(payload: Record<string, unknown>, cwd: string, home = homedir()): { key: string; entry: ClientServerEntry } | undefined {
  const roots = Array.isArray(payload.workspace_roots) ? payload.workspace_roots.filter((root): root is string => typeof root === "string") : [];
  const servers: Record<string, ClientServerEntry> = {};
  for (const path of [join(home, ".cursor", "mcp.json"), ...[cwd, ...roots].map((root) => join(root, ".cursor", "mcp.json"))]) {
    try {
      if (!existsSync(path)) continue;
      const parsed = JSON.parse(readFileSync(path, "utf8")) as { mcpServers?: Record<string, ClientServerEntry> };
      Object.assign(servers, parsed.mcpServers ?? {});
    } catch {
      // An unreadable config only means the server is not recognized.
    }
  }
  const command = typeof payload.command === "string" ? payload.command : undefined;
  const url = typeof payload.url === "string" ? payload.url : undefined;
  if (command && servers[command]) return { key: command, entry: servers[command]! };
  for (const [key, entry] of Object.entries(servers)) {
    if (url && entry.url === url) return { key, entry };
    if (command && [entry.command, ...(entry.args ?? [])].filter(Boolean).join(" ") === command) return { key, entry };
  }
  return undefined;
}

function isPalizadeWrapperEntry(entry: ClientServerEntry | undefined): boolean {
  const tokens = [entry?.command ?? "", ...(entry?.args ?? [])];
  return tokens.includes("wrap") && tokens.some((token) => /palizade/iu.test(token));
}

/**
 * The engine target for an MCP tool seen through a hook. A server already wrapped by Palizade is
 * checked by its proxy, so the hook stands aside; anything else (remote servers that sign in with
 * OAuth, servers the user did not wrap) is checked here as an untrusted server, recognized by the
 * catalog from the client's own config when possible.
 */
function mcpHookTarget(config: PalizadeConfig, serverName: string, cwd: string, known?: ClientServerEntry): { serverName: string; server: ServerConfig } | "wrapped" {
  if (config.servers[serverName]) return "wrapped";
  const entry = known ?? findClientServerEntry(serverName, cwd);
  if (isPalizadeWrapperEntry(entry)) return "wrapped";
  const server = serverConfigSchema.parse({
    ...(entry?.url ? { url: entry.url } : { command: entry?.command ?? `mcp:${serverName}`, args: entry?.args ?? [] }),
    trust: config.hooks.mcpTrust,
    cwd
  });
  return { serverName, server };
}

function normalizeToolInput(toolInput: unknown): Record<string, unknown> {
  if (toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)) {
    return toolInput as Record<string, unknown>;
  }
  if (typeof toolInput === "string") {
    return { command: toolInput };
  }
  return {};
}

function payloadField(payload: unknown, ...names: string[]): string | undefined {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  for (const name of names) {
    const value = record[name];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function enrichToolArguments(normalized: NormalizedNativeEvent): Record<string, unknown> {
  const input: Record<string, unknown> = { ...normalized.input };
  const command = typeof input.command === "string" ? input.command : undefined;
  if (command !== undefined && (normalized.tool === "Bash" || normalized.tool === "Shell" || normalized.tool === "shell")) {
    const analysis = analyzeShellCommand(command);
    if (analysis.urls.length > 0) input.urls = analysis.urls;
    if (analysis.hosts.length > 0) input.hosts = analysis.hosts;
    if (analysis.redirectTargets.length > 0) input.redirectTargets = analysis.redirectTargets;
    if (analysis.suspicious.length > 0) input.suspiciousPatterns = analysis.suspicious;
  }
  return input;
}

const PROMPT_EVENTS: Record<NativeClient, string> = {
  "claude-code": "UserPromptSubmit",
  codex: "UserPromptSubmit",
  cursor: "beforeSubmitPrompt"
};

export function isPromptEvent(client: NativeClient, event: string): boolean {
  return PROMPT_EVENTS[client] === event;
}

/**
 * Remembers the destinations a user typed (email addresses, urls, hosts, handles, account
 * numbers) so later sink calls to them are not treated as copied from untrusted content.
 * Never blocks the prompt: any failure only means nothing is remembered.
 */
export function recordUserPrompt(config: PalizadeConfig, client: NativeClient, payload: unknown, sessionId?: string): HookDecisionOutput {
  const allow: HookDecisionOutput = { exitCode: 0, output: client === "cursor" ? { continue: true } : undefined, reason: "Prompt recorded." };
  if (!config.taint.userIntent.enabled) return { ...allow, reason: "User intent tracking is off." };
  const prompt = payloadField(payload, "prompt", "user_prompt", "message");
  if (!prompt) return { ...allow, reason: "No prompt text." };
  const observables = extractStatedObservables(prompt);
  if (observables.length === 0) return allow;
  const store = new SqliteTaintStore(config.taint.sqlite, {
    scope: config.taint.scope,
    profileId: config.taint.profileId,
    keyPath: config.taint.keyPath,
    ttlMs: config.taint.ttlMs,
    sessionScope: "client",
    ...(process.env.PALIZADE_RUN_ID ? { runId: process.env.PALIZADE_RUN_ID } : {})
  });
  try {
    store.addUserStatements(sessionId ?? payloadField(payload, "session_id", "conversation_id") ?? "native-session", observables, config.taint.userIntent.ttlMs);
  } finally {
    store.close();
  }
  return { ...allow, reason: `Remembered ${observables.length} destination(s) from the prompt.` };
}

export async function evaluateHookEvent(input: {
  config: PalizadeConfig;
  client: NativeClient;
  event: string;
  payload: unknown;
  sessionId?: string;
  cwd?: string;
}): Promise<HookDecisionOutput> {
  if (isPromptEvent(input.client, input.event)) {
    try {
      return recordUserPrompt(input.config, input.client, input.payload, input.sessionId);
    } catch {
      return { exitCode: 0, output: input.client === "cursor" ? { continue: true } : undefined, reason: "Prompt not recorded." };
    }
  }
  const normalized = normalizeNativeEvent(input.client, input.event, input.payload);
  if (!normalized) {
    return { exitCode: 0, output: undefined, reason: "Unsupported hook event; no decision." };
  }
  const cwd = input.cwd ?? payloadField(input.payload, "cwd") ?? process.cwd();
  const sessionId = input.sessionId ?? payloadField(input.payload, "session_id", "conversation_id") ?? "native-session";

  const record = input.payload && typeof input.payload === "object" ? input.payload as Record<string, unknown> : {};
  const cursorServer = input.client === "cursor" && (input.event === "beforeMCPExecution" || input.event === "afterMCPExecution") ? cursorServerKey(record, cwd) : undefined;
  const mcp = input.client === "cursor" ? (cursorServer ? { server: cursorServer.key, tool: normalized.tool } : undefined) : parseMcpToolName(normalized.tool);
  const target = mcp ? mcpHookTarget(input.config, mcp.server, cwd, cursorServer?.entry) : undefined;
  if (target === "wrapped") {
    return { exitCode: 0, output: undefined, reason: "MCP server is wrapped by Palizade; its proxy checks this call." };
  }
  if (mcp) normalized.tool = mcp.tool;
  const context = await createHookEngine(input.config, sessionId, cwd, [], target);
  try {
    return await withHookTimeout(input.config.hooks.timeoutMs, async () => {
      const id = `hook-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
      const request: JsonRpcMessage = {
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: { name: normalized.tool, arguments: enrichToolArguments(normalized) }
      };
      const eventsBefore = context.events.length;
      const output = await context.engine.handleClientMessage(request);
      if (normalized.kind === "post") {
        const response: JsonRpcMessage = {
          jsonrpc: "2.0",
          id,
          result: normalized.response ?? { content: [{ type: "text", text: "" }] }
        };
        await context.engine.handleServerMessage(response);
        return { exitCode: 0, output: undefined, reason: "Tool output registered." };
      }
      if (output.toServer.length > 0) {
        return { exitCode: 0, output: undefined, reason: "Allowed by policy." };
      }
      const requestEvent = context.events.slice(eventsBefore).find((event) => event.direction === "request");
      const action = requestEvent?.action ?? "block";
      const reason = requestEvent?.reason ?? "Palizade blocked this native tool call.";
      if (action === "require_approval") {
        return buildAskOutput(input.client, input.event, reason);
      }
      return buildDenyOutput(input.client, input.event, reason);
    });
  } finally {
    context.close();
  }
}

async function withHookTimeout<T>(timeoutMs: number, run: () => Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`Hook evaluation timed out after ${timeoutMs}ms.`)), timeoutMs);
  });
  try {
    return await Promise.race([run(), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function buildDenyOutput(client: NativeClient, event: string, reason: string): HookDecisionOutput {
  if (client === "claude-code") {
    return {
      exitCode: 0,
      output: {
        hookSpecificOutput: {
          hookEventName: event,
          permissionDecision: "deny",
          permissionDecisionReason: reason
        }
      },
      reason
    };
  }
  if (client === "cursor") {
    return {
      exitCode: 0,
      output: { permission: "deny", user_message: reason, agent_message: reason },
      reason
    };
  }
  return {
    exitCode: 0,
    output: {
      hookSpecificOutput: {
        hookEventName: event,
        permissionDecision: "deny",
        permissionDecisionReason: reason
      }
    },
    reason
  };
}

function buildAskOutput(client: NativeClient, event: string, reason: string): HookDecisionOutput {
  if (client === "claude-code") {
    return {
      exitCode: 0,
      output: {
        hookSpecificOutput: {
          hookEventName: event,
          permissionDecision: "ask",
          permissionDecisionReason: reason
        }
      },
      reason
    };
  }
  if (client === "cursor") {
    return {
      exitCode: 0,
      output: { permission: "ask", user_message: reason, agent_message: reason },
      reason
    };
  }
  return {
    exitCode: 0,
    output: {
      hookSpecificOutput: {
        hookEventName: event,
        permissionDecision: "ask",
        permissionDecisionReason: reason
      }
    },
    reason
  };
}
