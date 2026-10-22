import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir, platform as osPlatform } from "node:os";
import { isAbsolute, resolve } from "node:path";
import {
  classifyToolDetailed,
  DEFAULT_METADATA_GUARD_CONFIG,
  InMemoryToolRegistry,
  reviewMetadata,
  type McpTool,
  type PalizadeConfig,
  type PalizadeLock
} from "@palizade/core";
import { HeuristicDetector, hasSecretLabel, SensitiveDataDetector } from "@palizade/detectors";
import { isPalizadeWrapper, resolveClientConfigPath } from "./install-config.js";

export type Severity = "high" | "medium" | "low" | "info";

export interface ScanFinding {
  severity: Severity;
  source: string;
  server: string;
  check: string;
  message: string;
  fix?: string | undefined;
}

export interface ScannedFile {
  client: string;
  path: string;
  scope: string;
  exists: boolean;
  servers: number;
}

export interface ScanResult {
  files: ScannedFile[];
  findings: ScanFinding[];
}

interface Location {
  client: string;
  path: string;
  scope: string;
  flags: string;
}

type JsonRecord = Record<string, unknown>;

const SEVERITY_ORDER: Severity[] = ["high", "medium", "low", "info"];
const secrets = new SensitiveDataDetector({ secrets: { enabled: true } });
const RUNNERS: Record<string, { skip: Set<string>; subcommand?: string }> = {
  npx: { skip: new Set(["-y", "--yes", "-q", "--quiet"]) },
  bunx: { skip: new Set(["-y", "--yes", "--bun"]) },
  uvx: { skip: new Set(["-q", "--quiet", "--offline"]) },
  pnpm: { skip: new Set(["-y", "--yes", "-s", "--silent"]), subcommand: "dlx" },
  yarn: { skip: new Set(["-q", "--quiet"]), subcommand: "dlx" },
  pipx: { skip: new Set(["-q", "--quiet"]), subcommand: "run" }
};
// docker and podman flags that take a value, so the image can be told apart from flag values.
const DOCKER_VALUE_FLAGS = new Set(["-e", "--env", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p", "--publish", "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "-l", "--label", "--platform", "--pull", "-m", "--memory", "--cpus", "--add-host", "--cap-add", "--cap-drop", "--security-opt", "--tmpfs", "--device", "--hostname", "-h"]);

export function clientLocations(options: { cwd?: string; homeDir?: string; platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv } = {}): Location[] {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = options.homeDir ?? homedir();
  const platform = options.platform ?? osPlatform();
  const env = options.env ?? process.env;
  const locations: Location[] = [];
  try {
    locations.push({ client: "claude-desktop", path: resolveClientConfigPath("claude-desktop", platform, env, home), scope: "user", flags: "" });
  } catch {
    // APPDATA missing on Windows: nothing to scan for Claude Desktop.
  }
  locations.push(
    { client: "claude-code", path: resolveClientConfigPath("claude-code", platform, env, home), scope: "user", flags: " --client claude-code" },
    { client: "claude-code", path: resolveClientConfigPath("claude-code", platform, env, home, cwd), scope: "project", flags: " --client claude-code --project" },
    { client: "cursor", path: resolveClientConfigPath("cursor", platform, env, home), scope: "user", flags: " --client cursor" },
    { client: "cursor", path: resolveClientConfigPath("cursor", platform, env, home, cwd), scope: "project", flags: " --client cursor --project" }
  );
  // Run from the home folder, project and user paths can be the same file.
  return locations.filter((location, index) => locations.findIndex((other) => other.path === location.path) === index);
}

export async function scanClientConfigs(locations: Location[]): Promise<ScanResult> {
  const files: ScannedFile[] = [];
  const findings: ScanFinding[] = [];
  for (const location of locations) {
    if (!existsSync(location.path)) {
      files.push({ ...location, exists: false, servers: 0 });
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(location.path, "utf8"));
    } catch (error) {
      files.push({ ...location, exists: true, servers: 0 });
      findings.push({ severity: "medium", source: location.path, server: "-", check: "unreadable-config", message: `Could not parse this file: ${error instanceof Error ? error.message : String(error)}` });
      continue;
    }
    const groups: Array<{ scope: string; flags: string; servers: JsonRecord }> = [];
    if (isRecord(parsed) && isRecord(parsed.mcpServers)) groups.push({ scope: location.scope, flags: location.flags, servers: parsed.mcpServers });
    // Claude Code's local scope: one server list per project directory inside ~/.claude.json.
    if (location.client === "claude-code" && location.scope === "user" && isRecord(parsed) && isRecord(parsed.projects)) {
      for (const [dir, project] of Object.entries(parsed.projects)) {
        if (isRecord(project) && isRecord(project.mcpServers) && Object.keys(project.mcpServers).length > 0) {
          groups.push({ scope: `local ${dir}`, flags: ` --client claude-code --local (run in ${dir})`, servers: project.mcpServers });
        }
      }
    }
    let count = 0;
    for (const group of groups) {
      for (const [name, entry] of Object.entries(group.servers)) {
        count += 1;
        const source = `${location.client} ${group.scope}`;
        findings.push(...checkClientEntry(source, name, entry, group.flags));
      }
    }
    files.push({ ...location, exists: true, servers: count });
  }
  return { files, findings };
}

export function checkClientEntry(source: string, name: string, entry: unknown, installFlags = ""): ScanFinding[] {
  if (!isRecord(entry)) return [{ severity: "medium", source, server: name, check: "invalid-entry", message: "This entry is not an object." }];
  const findings: ScanFinding[] = [];
  const wrapped = isPalizadeWrapper(entry);
  if (!wrapped) {
    const unsupported = entry.type === "sse" || entry.type === "ws";
    findings.push(unsupported
      ? { severity: "medium", source, server: name, check: "unsupported-transport", message: `Uses the legacy '${String(entry.type)}' transport, which Palizade cannot proxy, so it runs unprotected.`, fix: "Ask the server's maintainer for a Streamable HTTP endpoint, or remove the server." }
      : { severity: "medium", source, server: name, check: "unprotected", message: "Not routed through Palizade.", fix: `palizade install-config --all${installFlags}` });
  } else {
    const args = Array.isArray(entry.args) ? entry.args.filter((arg): arg is string => typeof arg === "string") : [];
    const configIndex = args.findIndex((arg) => arg === "-c" || arg === "--config");
    const configPath = configIndex >= 0 ? args[configIndex + 1] : undefined;
    if (configPath && isAbsolute(configPath) && !existsSync(configPath)) {
      findings.push({ severity: "high", source, server: name, check: "missing-palizade-config", message: `The wrapper points at ${configPath}, which does not exist, so the server will fail to start.`, fix: "Re-run palizade install-config from the folder that holds palizade.yaml." });
    }
  }
  findings.push(...checkServerDefinition(source, name, {
    command: typeof entry.command === "string" ? entry.command : undefined,
    args: Array.isArray(entry.args) ? entry.args.filter((arg): arg is string => typeof arg === "string") : [],
    env: stringValues(entry.env),
    headers: stringValues(entry.headers),
    url: typeof entry.url === "string" ? entry.url : undefined
  }));
  return findings;
}

/** Checks shared by client entries and palizade.yaml servers: plaintext secrets, unpinned code, insecure urls. */
export function checkServerDefinition(source: string, name: string, server: { command?: string | undefined; args: string[]; env: Record<string, string>; headers: Record<string, string>; url?: string | undefined }): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const plaintext: string[] = [];
  const candidates: Array<[string, string]> = [
    ...Object.entries(server.env).map(([key, value]): [string, string] => [`env.${key}`, `${key}=${value}`]),
    ...Object.entries(server.headers).map(([key, value]): [string, string] => [`headers.${key}`, `${key}: ${value}`]),
    ...server.args.map((arg, index): [string, string] => [`args[${index}]`, arg]),
    ...(server.url ? [["url", server.url] as [string, string]] : [])
  ];
  for (const [field, text] of candidates) {
    const withoutPlaceholders = text.replace(/\$\{(env:)?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}/gu, "");
    if (hasSecretLabel(secrets.detect(withoutPlaceholders).labels)) plaintext.push(field);
  }
  if (plaintext.length > 0) {
    findings.push({ severity: "high", source, server: name, check: "plaintext-secret", message: `Looks like a credential written directly in the config (${plaintext.join(", ")}). Anyone or anything that can read this file can use it.`, fix: "Move it to an environment variable and reference it as ${NAME}; then rotate the old value." });
  }
  const unpinned = unpinnedPackage(server.command, server.args);
  if (unpinned) {
    findings.push({ severity: "low", source, server: name, check: "unpinned-package", message: `Runs '${unpinned}' without a fixed version, so every start can pull a new release, including a compromised one.`, fix: `Pin a version, for example ${unpinned.startsWith("@") || !unpinned.includes("==") ? `${unpinned}@<version>` : unpinned}, and update it on purpose.` });
  }
  const image = unpinnedImage(server.command, server.args);
  if (image) {
    findings.push({ severity: "low", source, server: name, check: "unpinned-image", message: `Uses the container image '${image}' without a fixed tag or digest.`, fix: "Pin a version tag, or better a digest (image@sha256:...)." });
  }
  if (server.url) {
    try {
      const url = new URL(server.url.replace(/\$\{[^}]*\}/gu, "x"));
      if (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
        findings.push({ severity: "high", source, server: name, check: "insecure-url", message: `Talks to ${url.host} over plain http, so tokens and data can be read or changed on the network.`, fix: "Use https." });
      }
    } catch {
      findings.push({ severity: "low", source, server: name, check: "invalid-url", message: "The url could not be parsed." });
    }
  }
  return findings;
}

export function unpinnedPackage(command: string | undefined, args: string[]): string | undefined {
  if (!command) return undefined;
  const runner = RUNNERS[commandName(command).replace(/\.(cmd|exe)$/iu, "").toLowerCase()];
  if (!runner) return undefined;
  let rest = [...args];
  if (runner.subcommand) {
    const index = rest.indexOf(runner.subcommand);
    if (index < 0) return undefined;
    rest = rest.slice(index + 1);
  }
  const fromIndex = rest.indexOf("--from");
  const spec = fromIndex >= 0 ? rest[fromIndex + 1] : rest.find((arg) => !arg.startsWith("-") && !runner.skip.has(arg));
  if (!spec || spec.startsWith(".") || spec.startsWith("/") || /^[A-Za-z]:[\\/]/u.test(spec) || spec.includes("://")) return undefined;
  const versioned = /==|@[^/]*\d/u.test(spec.startsWith("@") ? spec.slice(1) : spec) && !/@latest$/u.test(spec);
  return versioned ? undefined : spec.replace(/@latest$/u, "");
}

export function unpinnedImage(command: string | undefined, args: string[]): string | undefined {
  if (!command || !/^(docker|podman)(\.exe)?$/iu.test(commandName(command))) return undefined;
  const runIndex = args.indexOf("run");
  if (runIndex < 0) return undefined;
  for (let index = runIndex + 1; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg.startsWith("-")) {
      if (DOCKER_VALUE_FLAGS.has(arg)) index += 1;
      continue;
    }
    if (arg.includes("@sha256:")) return undefined;
    const lastPart = arg.slice(arg.lastIndexOf("/") + 1);
    return !lastPart.includes(":") || lastPart.endsWith(":latest") ? arg : undefined;
  }
  return undefined;
}

/** Reviews palizade.yaml servers and their locked tool metadata, without starting anything. */
export async function scanPalizadeConfig(config: Pick<PalizadeConfig, "servers">, lock: PalizadeLock, source = "palizade.yaml"): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const detector = new HeuristicDetector();
  const registry = new InMemoryToolRegistry();
  const serverNames = Object.keys(config.servers);
  for (const [name, server] of Object.entries(config.servers)) {
    findings.push(...checkServerDefinition(source, name, { command: server.command, args: server.args, env: server.env, headers: server.headers ?? {}, url: server.url }));
    const locked = lock.servers[name]?.tools ?? {};
    if (Object.keys(locked).length === 0) {
      findings.push({ severity: "info", source, server: name, check: "not-locked", message: "No approved tool list yet, so tool descriptions were not reviewed.", fix: `palizade lock approve ${name}` });
      continue;
    }
    const tools = Object.entries(locked).map(([toolName, entry]) => ({ ...(entry.snapshot ?? {}), name: toolName }) as unknown as McpTool);
    const review = await reviewMetadata(tools.map((tool) => ({ name: tool.name, value: tool })), {
      serverName: name,
      configuredServers: serverNames,
      registry,
      config: DEFAULT_METADATA_GUARD_CONFIG,
      tools: true,
      detect: (text) => detector.detect(text, { server: name, trust: server.trust, surface: "tool_description" })
    });
    for (const item of review.items.filter((entry) => entry.flagged)) {
      const why = [
        item.hiddenUnicode.count > 0 ? "hidden characters" : "",
        item.shadows.length > 0 ? `mentions another server's tool (${item.shadows.map((shadow) => `${shadow.server}/${shadow.tool}`).join(", ")})` : "",
        item.collidesWith.length > 0 ? `same name as a tool on ${item.collidesWith.join(", ")}` : "",
        item.dangerousDefaults.length > 0 ? "risky default argument values" : ""
      ].filter(Boolean).join("; ");
      findings.push({ severity: item.hiddenUnicode.count > 0 || item.shadows.length > 0 ? "high" : "medium", source, server: name, check: "tool-metadata", message: `Tool ${item.name}: ${why}.`, fix: `palizade lock diff ${name}` });
    }
    let unknown = 0;
    for (const tool of tools) {
      const text = [tool.title ?? "", tool.description ?? ""].join("\n");
      const detection = await detector.detect(text, { server: name, tool: tool.name, trust: server.trust, surface: "tool_description" });
      if (detection.score >= 0.55) {
        findings.push({ severity: "high", source, server: name, check: "instruction-like-description", message: `Tool ${tool.name}: its description reads like instructions to the agent (${detection.labels.join(", ") || "score " + detection.score.toFixed(2)}).`, fix: `Read it with palizade lock diff ${name} before using this server.` });
      }
      if (classifyToolDetailed(tool.name, server, tool).toolClass === "unknown") unknown += 1;
    }
    if (unknown > 0) {
      findings.push({ severity: server.trust === "trusted" ? "info" : "low", source, server: name, check: "unknown-tools", message: `${unknown} tool(s) could not be classified; the default policy ${server.trust === "untrusted" ? "blocks" : server.trust === "semi" ? "asks about" : "only logs"} them.`, fix: `palizade tools ${name}` });
    }
  }
  return findings;
}

export function sortFindings(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export function formatScan(result: ScanResult): string {
  const lines: string[] = ["Scanned:"];
  for (const file of result.files) {
    lines.push(`  ${file.exists ? "found  " : "missing"} ${file.client} ${file.scope}: ${file.path}${file.exists ? ` (${file.servers} server${file.servers === 1 ? "" : "s"})` : ""}`);
  }
  const findings = sortFindings(result.findings);
  if (findings.length === 0) {
    lines.push("", "No findings.");
    return lines.join("\n");
  }
  const counts = SEVERITY_ORDER.map((severity) => `${findings.filter((finding) => finding.severity === severity).length} ${severity}`).join(", ");
  lines.push("", `Findings: ${counts}`);
  for (const finding of findings) {
    lines.push(`  [${finding.severity.toUpperCase()}] ${finding.server} (${finding.source}): ${finding.message}`);
    if (finding.fix) lines.push(`         fix: ${finding.fix}`);
  }
  return lines.join("\n");
}

// Client configs written on Windows use backslashes even when scanned elsewhere.
function commandName(command: string): string {
  return command.split(/[\\/]/u).pop() ?? command;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValues(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

