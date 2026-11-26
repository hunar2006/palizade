import { StaticApprovalProvider } from "@palizade/approvals";
import { createHash } from "node:crypto";
import { AuditLogger, JsonlAuditSink, SqliteAuditSink, type AuditEvent } from "@palizade/audit";
import { parsePolicy, type PolicyDocument } from "@palizade/policy";
import { SqliteTaintStore, canonicalHost, extractDestinationObservables, extractStatedObservables, isLoopbackHost, isSubstringsTruncated, normalizeText, trimMatchedUrl } from "@palizade/taint";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";
import { createDetector } from "./factory.js";
import { configSource, serverConfigSchema, type PalizadeConfig, type ServerConfig } from "./config.js";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isIP } from "node:net";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { readSealSidecars, sealDrift, sealEnabled, sealPath } from "./canary.js";
import { LearnedEgress } from "./egress.js";
import type { JsonRpcMessage } from "./mcp.js";
import { isWorkspacePath, resolveArgumentPath } from "./protected-paths.js";
import { flattenArguments } from "./text.js";

export type NativeClient = "claude-code" | "cursor" | "codex" | "gemini";

export interface HookDecisionOutput {
  exitCode: 0 | 2;
  output: unknown;
  reason: string;
}

export interface HookSamplingMetadata {
  sampled?: boolean;
  destinations?: string[];
}

export interface HookEngineContext {
  engine: InterceptionEngine;
  taintStore: SqliteTaintStore;
  events: AuditEvent[];
  close: () => void;
}

const SHELL_TOOLS = new Set(["Bash", "PowerShell", "Shell", "shell", "run_shell_command"]);
const SHELL_CAPABILITIES: ServerConfig["toolCapabilities"][string] = ["executes_code", "network_egress", "writes_local"];
const SHELL_ROLES: ServerConfig["argumentRoles"][string] = {
  command: "shell_command", decodedCommand: "shell_command", urls: "url", hosts: "hostname", redirectTargets: "file_path"
};
const UNTRUSTED_AGENT_TOOLS = new Set([
  "WebFetch", "WebSearch", "ReadMcpResourceTool", "ReadMcpResourceDirTool", "ListMcpResourcesTool", "Monitor"
]);

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
    PowerShell: "sink",
    Shell: "sink",
    shell: "sink",
    Write: "sink",
    Edit: "sink",
    MultiEdit: "sink",
    NotebookEdit: "sink",
    apply_patch: "sink",
    WebFetch: "sink",
    WebSearch: "source",
    Read: "source",
    Grep: "source",
    Glob: "source",
    Agent: "source",
    ReadMcpResourceTool: "source",
    ReadMcpResourceDirTool: "source",
    ListMcpResourcesTool: "source",
    // Gemini CLI built in tools.
    run_shell_command: "sink",
    write_file: "sink",
    replace: "sink",
    web_fetch: "sink",
    read_file: "source",
    read_many_files: "source",
    list_directory: "source",
    glob: "source",
    grep_search: "source",
    google_web_search: "source"
  },
  toolCapabilities: {
    Bash: SHELL_CAPABILITIES,
    PowerShell: SHELL_CAPABILITIES,
    Shell: SHELL_CAPABILITIES,
    shell: SHELL_CAPABILITIES,
    Write: ["file_write", "writes_local"],
    Edit: ["file_write", "writes_local"],
    MultiEdit: ["file_write", "writes_local"],
    NotebookEdit: ["file_write", "writes_local"],
    apply_patch: ["file_write", "writes_local"],
    WebFetch: ["network_egress", "reads_untrusted_content"],
    WebSearch: ["reads_untrusted_content", "network_egress"],
    Agent: ["reads_untrusted_content"],
    ReadMcpResourceTool: ["reads_untrusted_content"],
    ReadMcpResourceDirTool: ["reads_untrusted_content"],
    ListMcpResourcesTool: ["reads_untrusted_content"],
    run_shell_command: SHELL_CAPABILITIES,
    write_file: ["file_write", "writes_local"],
    replace: ["file_write", "writes_local"],
    web_fetch: ["network_egress", "reads_untrusted_content"]
  },
  argumentRoles: {
    Bash: SHELL_ROLES,
    PowerShell: SHELL_ROLES,
    Shell: SHELL_ROLES,
    shell: SHELL_ROLES,
    Write: { file_path: "file_path", path: "file_path", absolute_path: "file_path", content: "body" },
    Edit: { file_path: "file_path", path: "file_path", absolute_path: "file_path", old_string: "body", new_string: "body" },
    MultiEdit: { file_path: "file_path", path: "file_path", absolute_path: "file_path", "edits[*].old_string": "body", "edits[*].new_string": "body" },
    NotebookEdit: { notebook_path: "file_path", file_path: "file_path", new_source: "body" },
    apply_patch: { file_path: "file_path", path: "file_path", file_paths: "file_path", patch: "body", input: "body" },
    WebFetch: { url: "url" },
    WebSearch: { query: "http_query" },
    run_shell_command: SHELL_ROLES,
    write_file: { file_path: "file_path", path: "file_path", absolute_path: "file_path", content: "body" },
    replace: { file_path: "file_path", path: "file_path", absolute_path: "file_path", old_string: "body", new_string: "body" },
    // web_fetch takes a prompt with up to 20 urls; urls inside it are found as url fields.
    web_fetch: { prompt: "body" }
  },
  sensitive: false,
  sensitiveTools: {},
  sensitivePathPatterns: [],
  shell: false,
  allowShell: false
};

// A long running daemon reuses the parsed policy while the file text is unchanged.
let policyCache: { path: string; raw: string; policy: PolicyDocument } | undefined;
async function loadPolicyCached(path: string): Promise<PolicyDocument> {
  const raw = await readFile(path, "utf8");
  if (policyCache?.path !== path || policyCache.raw !== raw) policyCache = { path, raw, policy: parsePolicy(raw, path) };
  return structuredClone(policyCache.policy);
}

const HOOKS_DEFER = "native hooks defer approval decisions to the client";

export async function createHookEngine(
  config: PalizadeConfig,
  sessionId: string,
  cwd: string,
  capture: AuditEvent[] = [],
  target: { serverName: string; server: ServerConfig } = { serverName: "native-tools", server: { ...HOOK_SERVER, cwd } },
  approvedPolicy?: PolicyDocument,
  sealed?: { lockfile: LockfileStore; learnedEgress: LearnedEgress }
): Promise<HookEngineContext> {
  // shortcut: each hook call opens a fresh engine/store, also under `palizade daemon`; keep them open if shared split windows are required.
  const server = target.server;
  const policy = approvedPolicy ?? await loadPolicyCached(config.policy);
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
    approvals: new StaticApprovalProvider(false, HOOKS_DEFER),
    lockfile: sealed?.lockfile ?? new LockfileStore(config.lockfile),
    sealedLearnedEgress: sealed?.learnedEgress
  });
  return {
    engine,
    taintStore,
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
  readTargets: string[];
  downloads: ShellDownload[];
  copies: ShellFileCopy[];
  pathOperands: string[];
  executionOperands: string[];
  scriptFiles: string[];
  sensitiveRead: boolean;
  external: boolean;
  decodedCommand?: string;
  suspicious: string[];
}

interface ShellDownload {
  path: string;
  cwd: string;
  directory?: boolean;
  source?: string;
}

interface ShellFileCopy extends ShellDownload {
  source: string;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
const NETWORK_COMMAND = /^(?:curl|wget|nc|ncat|scp|ssh|rsync|ftp|sftp|ping|nslookup|dig|telnet|open|invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|bitsadmin|certutil|test-netconnection|tnc|resolve-dnsname|webclient|httpclient)$/iu;
const CURL_SHORT_VALUE_FLAG = /[AbcCdDeEFHKmoPQrTuwxXyYz]/u;
const WEB_REQUEST = /^(?:invoke-webrequest|invoke-restmethod|iwr|irm)$/iu;
const REMOTE_COMMAND = /^(?:gh|glab|aws|az|gcloud)$/iu;
const SHELL_WORDS = /"(?:""|[^"])*"|'(?:''|[^'])*'|[12]?>>?|<|\|[|&]?|[,;&()\r\n]|[^\s"'<>;,|&()]+/gu;
const FILE_READER = /^(?:cat|type|gc|get-content|pg|more|less|head|tail|bat|get-item|get-childitem|ls|dir|rg|grep|ag|findstr|select-string|sls|sed|awk|gawk|jq|yq|strings|import-csv)$/iu;
const PATTERN_FIRST_READER = /^(?:rg|grep|ag|findstr|select-string|sls|sed|awk|gawk|jq|yq)$/iu;
const PATTERN_VALUE_FLAGS = /^(?:-e|--regexp|-f|--file|-Pattern|-m|--max-count|-A|-B|-C|--after-context|--before-context|--context|-g|--glob|-t|--type|-T|--type-not|-F|--field-separator|-v|-Encoding)$/iu;
const PATTERN_INLINE_FLAGS = /^(?:-e|--regexp|-f|--file|-Pattern)$/iu;
const FILE_WRITER = /^(?:out-file|set-content|add-content|sc|ac)$/iu;
const TEXT_OUTPUT = /^(?:echo|printf|write-output|write-host)$/u;
const LOCATION_COMMAND = /^(?:cd|chdir|set-location|sl|pushd|push-location|pushl|popd|pop-location|popl)$/u;
const COPY_COMMAND = /^(?:cp|copy|copy-item|cpi|mv|move|move-item|mi|ren|rename|rename-item|rni)$/u;
const PYTHON_COMMAND = /^(?:python(?:3(?:\.\d+)?)?|py)$/u;
const NPM_INIT_VALUE_FLAG = /^(?:-w|--workspace|--scope|--init-(?:author-(?:name|email|url)|license|module|type|version))$/iu;
const POWERSHELL_COMMAND = /^(?:powershell|pwsh)$/u;
const SCRIPT_INTERPRETER = /^(?:bash|sh|zsh|fish|node|perl|ruby)$/u;
const DYNAMIC_PATH = /[$*?]|^%[^%]+%/u;
const NET_CLIENT = /\bNet\.(?:Http\.)?(?:WebClient|HttpClient)\b/iu;
const LISTING_INSPECTION_VERBS = new Set(["ls", "dir", "pwd", "get-childitem", "gci", "get-location", "gl"]);
const FILE_INSPECTION_VERBS = new Set(["cat", "type", "gc", "get-content", "head", "tail"]);
const SAFE_GIT_INSPECTION_SUBCOMMANDS = new Set(["status", "diff", "log", "show"]);
const DOS_DEVICE_NAME_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
// `$(...)` and `curl ... | sh` are checked in code below: as regexes they rescanned the rest of the
// command from every "$(" or "curl", which is quadratic on a long command.
const SUSPICIOUS_RE = /`[^`]+`|\beval\b|\bbase64\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\bperl\s+-e\b|\/dev\/tcp\b|\bchmod\s+[0-7]*[45][0-7]*\b/iu;

function suspiciousShell(command: string): boolean {
  const substitution = command.indexOf("$(");
  if (substitution >= 0 && command.indexOf(")", substitution + 2) >= 0) return true;
  if (SUSPICIOUS_RE.test(command)) return true;
  // A download piped straight into a shell: the stage after the one that runs curl or wget.
  const stages = command.split(/([|;])/u);
  for (let index = 0; index + 2 < stages.length; index += 2) {
    if (stages[index + 1] === "|" && /\b(?:curl|wget)\b/iu.test(stages[index]!) && /^\s*(?:bash|sh|zsh)\b/iu.test(stages[index + 2]!)) return true;
  }
  return false;
}

function unquoteShellWord(word: string): string {
  return word.replace(/^["']|["']$/gu, "");
}

function stripShellCarets(word: string): string {
  return word.startsWith("'") ? word : word.replace(/\^/gu, "");
}

function isEncodedCommandFlag(word: string): boolean {
  const normalized = stripShellCarets(unquoteShellWord(word)).split(":", 1)[0]!.toLowerCase();
  return normalized === "-e" || normalized === "-ec" || (normalized.startsWith("-en") && "-encodedcommand".startsWith(normalized));
}

function shellFileArguments(words: string[], singlePathGroup = false, patternFirst = false): string[] {
  const named = words.findIndex((word) => /^-(?:literalpath|filepath|path)(?::|$)/iu.test(word));
  const inline = words[named]?.split(/:(.*)/su)[1];
  let args: string[];
  if (named >= 0) {
    args = [...(inline ? [inline] : []), ...words.slice(named + 1)];
  } else {
    let sawPatternFlag = false;
    let skippedPattern = !patternFirst;
    args = [];
    for (let index = 0; index < words.length; index++) {
      const word = words[index]!;
      const prev = words[index - 1] ?? "";
      if (PATTERN_INLINE_FLAGS.test(prev) || PATTERN_INLINE_FLAGS.test(word)) sawPatternFlag = true;
      if (word.startsWith("-")) continue;
      if (/^(?:-n|-c|-tail|-totalcount|-encoding|-value|-width)$/iu.test(prev) || (patternFirst && PATTERN_VALUE_FLAGS.test(prev))) {
        if (/^(?:-f|--file)$/iu.test(prev)) args.push(word);
        continue;
      }
      if (patternFirst && !sawPatternFlag && !skippedPattern) {
        skippedPattern = true;
        continue;
      }
      args.push(word);
    }
  }
  if (named < 0 && !singlePathGroup) return args.filter((word) => word !== ",").map(unquoteShellWord);
  const targets: string[] = [];
  for (let index = 0; index < args.length; index += 2) {
    const word = args[index]!;
    if (word.startsWith("-") || word === ",") break;
    targets.push(unquoteShellWord(word));
    if (args[index + 1] !== ",") break;
  }
  return targets;
}

const FILE_INSPECTION_FLAGS = new Set([
  "-raw", "-b", "-e", "-s", "-t", "-u", "-v", "-q", "-a",
  "--quiet", "--silent", "--verbose", "--number", "--number-nonblank",
  "--squeeze-blank", "--show-ends", "--show-tabs", "--show-nonprinting"
]);

export function isPlainRelativeWorkspacePath(rawArg: string, cwd: string, allowDot = false): boolean {
  const unquoted = unquoteShellWord(rawArg);
  if (!unquoted || unquoted === "-" || unquoted.startsWith("-") || unquoted.startsWith("+")) return false;
  if (/^[/\\]/u.test(unquoted) || /^file:/iu.test(unquoted)) return false;
  if (/[\u0000-\u001F\u007F:~*?${}()<>|&;`%"']/u.test(unquoted)) return false;
  const segments = unquoted.split(/[/\\]/u);
  if (segments.some((segment) => segment === "" || segment === "..")) return false;
  if (!allowDot && segments.every((segment) => segment === ".")) return false;
  for (const segment of segments) {
    if (segment === ".") continue;
    if (/[. ]$/u.test(segment)) return false;
    if (DOS_DEVICE_NAME_RE.test(segment)) return false;
  }
  const resolved = resolveHookPath(unquoted, cwd);
  return !resolved.uncertain && isWorkspacePath(resolved, cwd) && !DEPENDENCY_FILE.test(resolved.canonical);
}

function parseShellHost(raw: string): string | undefined {
  const cleaned = stripShellCarets(unquoteShellWord(raw)).replace(/^-(?:uri|computername|name|source):/iu, "").trim();
  if (!cleaned || cleaned.startsWith("-")) return undefined;
  const bracketed = /^(\[[\da-f:.]+\])(?::\d+)?$/iu.exec(cleaned);
  if (bracketed) {
    const inner = bracketed[1]!.slice(1, -1);
    return isIP(inner) === 6 ? canonicalHost(bracketed[1]!) : undefined;
  }
  if (isIP(cleaned) === 6) return canonicalHost(`[${cleaned}]`);
  const userAtIpv6 = /^[a-z0-9._-]+@([\da-f:.]+)$/iu.exec(cleaned);
  if (userAtIpv6 && isIP(userAtIpv6[1]!) === 6) return canonicalHost(`[${userAtIpv6[1]!}]`);
  const withoutPort = cleaned.split("/", 1)[0]!.replace(/:\d+$/u, "");
  if (isIP(withoutPort) === 4) return canonicalHost(withoutPort);
  if (/^0x[\da-f]{1,8}$/iu.test(withoutPort)) return canonicalHost(withoutPort);
  if (/^\d{8,10}$/u.test(withoutPort)) {
    const numeric = Number(withoutPort);
    if (numeric >= 0x01000000 && numeric <= 0xffffffff) return canonicalHost(withoutPort);
  }
  if (/^(?:localhost|(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+(?:[\p{L}]{2,24}|xn--[\da-z]{1,59})\.?)$/iu.test(withoutPort)) {
    return canonicalHost(withoutPort);
  }
  return undefined;
}

function transferArguments(verb: string, args: string[]) {
  const operands: string[] = [];
  const outputs: string[] = [];
  const sources: string[] = [];
  const curlOutputs: Array<string | undefined> = [];
  let remoteNameAll = false;
  let inferRemoteNames = true;
  let outputSpecified = false;
  let outputDirectory: string | undefined;
  let options = true;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (options && arg === "--") {
      options = false;
      continue;
    }
    if (options && arg.startsWith("-")) {
      let flag = arg;
      let value: string | undefined;
      if (verb === "curl" && /^-[^-]/u.test(arg)) {
        const index = arg.search(CURL_SHORT_VALUE_FLAG);
        for (const letter of arg.slice(1, index === -1 ? undefined : index)) {
          if (letter === "O") curlOutputs.push(undefined);
          if (letter === "J") inferRemoteNames = false;
        }
        if (index !== -1) {
          flag = `-${arg[index]}`;
          value = arg.slice(index + 1) || undefined;
        }
      } else if (verb === "wget" && /^-[^-]/u.test(arg)) {
        const index = arg.search(/[OiP]/u);
        if (arg.slice(1, index === -1 ? undefined : index).includes("r")) inferRemoteNames = false;
        if (index !== -1) {
          flag = "-" + arg[index];
          value = arg.slice(index + 1) || undefined;
        }
      } else {
        const match = /^([^=:]+)[=:]([\s\S]*)$/u.exec(arg);
        if (match) {
          flag = match[1]!;
          value = match[2];
        }
      }
      if (WEB_REQUEST.test(verb)) flag = flag.toLowerCase();
      const output = verb === "curl" ? /^(?:-o|--output)$/u.test(flag)
        : verb === "wget" ? /^(?:-O|--output-document)$/u.test(flag) : flag === "-outfile";
      const localValue = verb === "curl" ? /^(?:-[TdFKE]|--(?:upload-file|data(?:-ascii|-binary|-raw|-urlencode)?|form(?:-string)?|config|cacert|cert|key))$/u.test(flag)
        : verb === "wget" ? /^(?:-i|--input-file)$/u.test(flag) : flag === "-infile";
      if (output || localValue) {
        const operand = value ?? args[++i];
        outputSpecified ||= output;
        if (output && operand) {
          if (verb === "curl") curlOutputs.push(operand);
          else if (operand !== "-") outputs.push(operand);
        }
        continue;
      }
      if ((verb === "curl" && flag === "--output-dir") || (verb === "wget" && /^(?:-P|--directory-prefix)$/u.test(flag))) {
        outputDirectory = value ?? args[++i];
        continue;
      }
      if (verb === "curl" && flag.length === 2 && CURL_SHORT_VALUE_FLAG.test(flag[1]!)) {
        const operand = value ?? args[++i];
        if (operand) operands.push(operand);
        continue;
      }
      if (verb === "curl" && flag === "--remote-name") curlOutputs.push(undefined);
      if (verb === "curl" && flag === "--remote-name-all") remoteNameAll = true;
      if (verb === "curl" && flag === "--remote-header-name" ||
          verb === "wget" && /^(?:--content-disposition|--recursive|--mirror|-m)$/u.test(flag)) inferRemoteNames = false;
      if ((verb === "curl" && flag === "--url") || (WEB_REQUEST.test(verb) && flag === "-uri")) {
        const operand = value ?? args[++i];
        if (operand) {
          operands.push(operand);
          sources.push(operand);
        }
        continue;
      }
      operands.push(arg);
      continue;
    }
    operands.push(arg);
    sources.push(arg);
  }
  for (const [i, source] of sources.entries()) {
    const curlOutput = curlOutputs[i];
    if (curlOutput) {
      if (curlOutput !== "-") outputs.push(curlOutput);
      continue;
    }
    if (!inferRemoteNames || (!(verb === "curl" && (i < curlOutputs.length || remoteNameAll)) && !(verb === "wget" && !outputSpecified))) continue;
    const url = URL.parse(source.includes("://") ? source : `http://${source}`);
    if (!url?.hostname) continue;
    const name = url.pathname.endsWith("/") ? (verb === "wget" ? "index.html" : "") : basename(url.pathname);
    if (name) outputs.push(name);
  }
  return { operands, outputs: outputDirectory ? outputs.map((path) => isAbsolute(path) ? path : join(outputDirectory, path)) : outputs };
}

function clonePath(args: string[], submodule: boolean): string | undefined {
  const operands: string[] = [];
  let options = true;
  for (let i = 0; i < args.length && operands.length < 2; i++) {
    const arg = args[i]!;
    if (options && arg === "--") {
      options = false;
    } else if (options && /^(?:-[bocjru]|--(?:branch|origin|config|jobs|upload-pack|reference(?:-if-able)?|separate-git-dir|depth|shallow-since|shallow-exclude|filter|ref-format|revision|template|name))$/u.test(arg)) {
      i++;
    } else if (!options || !arg.startsWith("-")) {
      operands.push(arg);
    }
  }
  const [repo, target] = operands;
  if (target || !repo) return target;
  const url = URL.parse(repo);
  const name = basename((url?.hostname ? url.pathname : repo.replace(/^[^/\\]+:(?![\\/])/u, "")).replace(/\\/gu, "/"));
  const base = name.replace(/\.git$/u, "");
  return base ? base + (!submodule && args.includes("--bare") ? ".git" : "") : undefined;
}

function tarArguments(args: string[]) {
  let archive: string | undefined;
  let path = ".";
  let extract = false;
  let pack = false;
  const inputs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--") {
      inputs.push(...args.slice(i + 1));
      break;
    }
    if (arg === "--extract" || arg === "--get") extract = true;
    else if (/^--(?:create|append|update)$/u.test(arg)) pack = true;
    else if (arg === "--file") archive = args[++i];
    else if (arg.startsWith("--file=")) archive = arg.slice(7);
    else if (arg === "-C" || arg === "--directory") path = args[++i] ?? path;
    else if (arg.startsWith("--directory=")) path = arg.slice(12);
    else if (arg.startsWith("-C")) path = arg.slice(2);
    else if (/^(?:-T|-X|--files-from|--exclude|--exclude-from)$/u.test(arg)) i++;
    else if (/^-[^-]/u.test(arg) || (i === 0 && /^[a-z]+$/iu.test(arg))) {
      const flags = arg.replace(/^-/u, "");
      const f = flags.indexOf("f");
      const modes = f === -1 || !arg.startsWith("-") ? flags : flags.slice(0, f);
      extract ||= modes.includes("x");
      pack ||= /[cru]/u.test(modes);
      if (f !== -1) archive = (arg.startsWith("-") ? flags.slice(f + 1) : "") || args[++i];
    } else if (!arg.startsWith("-")) inputs.push(arg);
  }
  return { archive, path, extract, pack, inputs };
}

function archiveInputs(verb: string, args: string[]): string[] {
  if (verb === "zip") {
    if (args.includes("-d")) return [];
    const patterns = args.findIndex((arg) => /^-[xi]/u.test(arg));
    return (patterns < 0 ? args : args.slice(0, patterns)).filter((arg) => !arg.startsWith("-")).slice(1);
  }
  if (/^(?:7z|7za|7zz)$/u.test(verb)) {
    const positional = args.filter((arg) => !arg.startsWith("-") && arg !== ",");
    return /^(?:a|u)$/iu.test(positional[0] ?? "") ? positional.slice(2) : [];
  }
  if (verb !== "compress-archive") return [];
  const inputs: string[] = [];
  let namedDestination = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const flag = /^-(path|literalpath|destinationpath|compressionlevel)(?::(.*))?$/iu.exec(arg);
    if (flag) {
      const name = flag[1]!.toLowerCase();
      const value = flag[2] || args[++i];
      if (name === "destinationpath") namedDestination = true;
      else if (value && (name === "path" || name === "literalpath")) inputs.push(value);
    } else if (!arg.startsWith("-") && arg !== ",") inputs.push(arg);
  }
  return namedDestination ? inputs : inputs.slice(0, -1);
}

function archiveExtraction(verb: string, args: string[], cwd: string, tar: ReturnType<typeof tarArguments> | undefined): ShellDownload | undefined {
  let archive: string | undefined;
  let path = ".";
  if (tar) {
    if (!tar.extract) return undefined;
    ({ archive, path } = tar);
  } else if (verb === "unzip") {
    if (args.some((arg) => /^-[^-]*[lptz]/u.test(arg))) return undefined;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!;
      if (arg === "-d") path = args[++i] ?? path;
      else if (arg.startsWith("-d")) path = arg.slice(2);
      else if (arg === "-P") i++;
      else if (!arg.startsWith("-")) archive ??= arg;
    }
  } else if (verb === "expand-archive") {
    let target: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!;
      const flag = /^-(path|literalpath|destinationpath)(?::(.*))?$/iu.exec(arg);
      if (flag) {
        const value = flag[2] || args[++i];
        if (flag[1]!.toLowerCase() === "destinationpath") target = value;
        else archive = value;
      } else if (!arg.startsWith("-")) {
        if (!archive) archive = arg;
        else target ??= arg;
      }
    }
    if (archive) path = target ?? basename(archive.replace(/\\/gu, "/"), ".zip");
  }
  return archive && archive !== "-" ? { path, cwd, directory: true, source: archive } : undefined;
}

function shellFileCopies(verb: string, args: string[], cwd: string): ShellFileCopy[] {
  const positional: string[] = [];
  let namedSource: string | undefined;
  let namedTarget: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const flag = /^-(path|literalpath|destination|newname)(?::(.*))?$/iu.exec(arg);
    if (flag) {
      const value = flag[2] || args[++i];
      if (/^(?:path|literalpath)$/iu.test(flag[1]!)) namedSource = value;
      else namedTarget = value;
    } else if (!arg.startsWith("-") && arg !== "," && !(/^\/[YN]$/iu.test(arg) && /^(?:copy|move)$/u.test(verb))) {
      positional.push(arg);
    }
  }
  const target = namedTarget ?? positional.pop();
  const sources = namedSource ? [namedSource, ...positional] : positional;
  if (!target || sources.length === 0 || DYNAMIC_PATH.test(target)) return [];
  const renames = /^(?:ren|rename|rename-item|rni)$/u.test(verb);
  const targetPath = resolveHookPath(target, cwd);
  let intoDirectory = !renames && (sources.length > 1 || /[\\/]$/u.test(target));
  if (!renames && !intoDirectory && !targetPath.uncertain) {
    try { intoDirectory = statSync(targetPath.canonical, { throwIfNoEntry: false })?.isDirectory() ?? false; }
    catch { return []; }
  }
  return sources.filter((source) => !DYNAMIC_PATH.test(source)).map((source) => ({
    source, cwd,
    path: renames && !/[\\/]/u.test(target) ? join(dirname(source.replace(/\\/gu, "/")), target)
      : intoDirectory ? join(target, basename(source.replace(/\\/gu, "/"))) : target
  }));
}

export function isSafeInspectionShellCommand(command: string, cwd = process.cwd()): boolean {
  const trimmed = command.trim();
  if (!trimmed || /[\u0000-\u001F\u007F\r\n|&;<>`]/u.test(trimmed) || trimmed.includes("$(") || trimmed.includes("${")) return false;
  const words = trimmed.match(SHELL_WORDS) ?? [];
  if (words.length === 0) return false;
  if (words.some((word) => /^[;|&()\r\n<>]$|^[12]?>>?$/u.test(word))) return false;
  const rawHead = unquoteShellWord(words[0]!);
  if (/[\\/]/u.test(rawHead)) return false;
  const verb = stripShellCarets(rawHead).replace(/\.(?:exe|cmd)$/iu, "").toLowerCase();

  if (verb === "git") {
    const subcommand = words[1] ? stripShellCarets(unquoteShellWord(words[1])).toLowerCase() : "";
    if (!SAFE_GIT_INSPECTION_SUBCOMMANDS.has(subcommand)) return false;
    let afterDashDash = false;
    let hasNoIndex = false;
    const noIndexPaths: string[] = [];
    for (let i = 2; i < words.length; i++) {
      const raw = unquoteShellWord(words[i]!);
      const exact = stripShellCarets(raw);
      const lower = exact.toLowerCase();
      if (!afterDashDash && exact === "--") {
        afterDashDash = true;
        continue;
      }
      if (!afterDashDash && exact.startsWith("-")) {
        if (exact === "-c" || (exact.startsWith("-c") && !exact.startsWith("--")) ||
            lower.startsWith("--config") ||
            lower === "--ext-diff" || lower.startsWith("--ext-diff=") ||
            lower.startsWith("--output") ||
            lower.startsWith("--exec") ||
            lower === "--textconv" || lower.startsWith("--textconv=") ||
            lower === "--git-dir" || lower.startsWith("--git-dir=") ||
            lower === "--work-tree" || lower.startsWith("--work-tree=")) {
          return false;
        }
        if (lower === "--no-index") hasNoIndex = true;
        continue;
      }
      if (hasNoIndex) {
        if (!isPlainRelativeWorkspacePath(raw, cwd)) return false;
        noIndexPaths.push(raw);
      }
    }
    return !hasNoIndex || noIndexPaths.length > 0;
  }

  if (FILE_INSPECTION_VERBS.has(verb)) {
    let afterDashDash = false;
    const paths: string[] = [];
    for (let i = 1; i < words.length; i++) {
      const word = words[i]!;
      const unquoted = unquoteShellWord(word);
      const lower = stripShellCarets(unquoted).toLowerCase();
      if (!afterDashDash && unquoted === "--") {
        afterDashDash = true;
        continue;
      }
      if (!afterDashDash && unquoted.startsWith("-")) {
        const inlinePath = /^-(?:path|literalpath):(.*)$/iu.exec(unquoted);
        if (inlinePath) {
          if (!inlinePath[1]) return false;
          paths.push(inlinePath[1]);
          continue;
        }
        if (lower === "-path" || lower === "-literalpath") {
          const next = words[++i];
          if (!next) return false;
          paths.push(next);
          continue;
        }
        if (/^(?:-[nc]|--(?:lines|bytes))=[+-]?\d+[kmgb]?$/iu.test(lower) ||
            /^-[nc]\d+[kmgb]?$/iu.test(lower) ||
            /^-(?:totalcount|head|tail|readcount)(?::|=)\d+$/iu.test(lower) ||
            /^-(?:encoding|delimiter)[:=]\S+$/iu.test(lower)) {
          continue;
        }
        if (/^(?:-n|-c|--lines|--bytes|-totalcount|-head|-tail|-readcount)$/iu.test(lower)) {
          const next = words[i + 1] ? unquoteShellWord(words[i + 1]!) : "";
          if (/^[+-]?\d+[kmgb]?$/iu.test(next)) {
            i++;
            continue;
          }
          if (lower === "-n") continue;
          return false;
        }
        if (lower === "-encoding" || lower === "--encoding") {
          const next = words[++i];
          if (!next || !/^[a-z0-9_-]+$/iu.test(unquoteShellWord(next))) return false;
          continue;
        }
        if (FILE_INSPECTION_FLAGS.has(lower)) continue;
        return false;
      }
      paths.push(word);
    }
    return paths.length > 0 && paths.every((path) => isPlainRelativeWorkspacePath(path, cwd));
  }

  if (LISTING_INSPECTION_VERBS.has(verb)) {
    const locationOnly = verb === "pwd" || verb === "get-location" || verb === "gl";
    for (let i = 1; i < words.length; i++) {
      const unquoted = unquoteShellWord(words[i]!);
      if (unquoted.startsWith("-")) {
        if (/^-(?:stream|filter)$/iu.test(unquoted)) return false;
        if (/^-(?:path|literalpath):(.*)$/iu.test(unquoted)) {
          const value = unquoted.split(/:(.*)/u)[1] ?? "";
          if (locationOnly || (value !== "." && !isPlainRelativeWorkspacePath(value, cwd, true))) return false;
        } else if (/^-(?:path|literalpath)$/iu.test(unquoted)) {
          const next = words[++i];
          if (locationOnly || !next || (unquoteShellWord(next) !== "." && !isPlainRelativeWorkspacePath(next, cwd, true))) return false;
        }
        continue;
      }
      if (locationOnly) return false;
      if (unquoted !== "." && !isPlainRelativeWorkspacePath(words[i]!, cwd, true)) return false;
    }
    return true;
  }

  return false;
}

const DOCKER_VALUE_FLAGS = new Set(["-h", "--host", "-c", "--context", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"]);
const KUBECTL_VALUE_FLAGS = new Set(["-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server", "--token", "--as", "--as-group", "--certificate-authority", "--client-certificate", "--client-key", "-v", "--v"]);
const GIT_HISTORY_VALUE_FLAGS = new Set(["-n", "-L", "-S", "-G", "--max-count", "--since", "--after", "--until", "--before", "--author", "--committer", "--grep", "--format", "--pretty"]);

function shellToolSubcommand(args: string[], valueFlags: Set<string>): string {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--") break;
    if (valueFlags.has(arg.toLowerCase())) {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    return arg.toLowerCase();
  }
  return "";
}

function readGitRemotes(cwd: string): Set<string> {
  const remotes = new Set(["origin", "upstream"]);
  let current = resolve(cwd);
  for (let depth = 0; depth < 8; depth++) {
    const gitEntry = join(current, ".git");
    if (existsSync(gitEntry)) {
      try {
        let configPath = join(gitEntry, "config");
        if (lstatSync(gitEntry).isFile()) {
          const gitdir = /^gitdir:\s*(.+)$/imu.exec(readFileSync(gitEntry, "utf8"))?.[1]?.trim();
          if (gitdir) configPath = join(isAbsolute(gitdir) ? gitdir : resolve(current, gitdir), "config");
        }
        if (existsSync(configPath)) {
          for (const match of readFileSync(configPath, "utf8").matchAll(/^\[remote\s+"([^"]+)"\]/gmu)) {
            remotes.add(match[1]!.toLowerCase());
          }
        }
      } catch {
        // Fall back to default remote names if git metadata cannot be read.
      }
      break;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return remotes;
}

function referencesRemoteGitRef(args: string[], startIndex: number, cwd: string): boolean {
  let remotes: Set<string> | undefined;
  for (let i = startIndex; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--") break;
    if (GIT_HISTORY_VALUE_FLAGS.has(arg)) {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    const revExpr = arg.split(":", 1)[0] ?? "";
    for (const rawPart of revExpr.split(/\.{2,3}/u)) {
      const part = rawPart.trim().replace(/[~^].*$/u, "");
      if (!part) continue;
      if (/^fetch_head$/iu.test(part) || /@\{(?:u|upstream)\}/iu.test(rawPart) || /^(?:refs\/)?remotes\//iu.test(part)) {
        return true;
      }
      if (part.includes("/") && !part.startsWith("/") && !part.startsWith("./") && !part.startsWith("../")) {
        remotes ??= readGitRemotes(cwd);
        const prefix = part.split("/", 1)[0]!.toLowerCase();
        if (remotes.has(prefix)) return true;
      }
    }
  }
  return false;
}

export function analyzeShellCommand(command: string, decode = true, cwd = process.cwd()): ShellAnalysis {
  // shortcut: heuristic shell extraction misses complex quoting and indirect destinations, use a shell parser if supported command forms require it.
  const stages: Array<{ words: string[]; separator?: string }> = [{ words: [] }];
  for (const word of command.match(SHELL_WORDS) ?? []) {
    if (/^(?:[;&()\r\n]|\|[|&]?)$/u.test(word)) stages.push({ words: [], separator: word });
    else stages.at(-1)!.words.push(word);
  }
  const commandName = stages.find((stage) => stage.words.length > 0)?.words[0];
  const urls: string[] = [...(command.match(URL_RE) ?? [])].map(trimMatchedUrl);
  const hosts: string[] = [];
  const redirectTargets: string[] = [];
  const readTargets: string[] = [];
  const downloads: ShellDownload[] = [];
  const copies: ShellFileCopy[] = [];
  const pathOperands: string[] = [];
  const executionOperands: string[] = [];
  const scriptFiles: string[] = [];
  const nestedSuspicious: string[] = [];
  const netClient = NET_CLIENT.test(command);
  let external = netClient;
  let sensitiveRead = false;
  let downloadStream = false;
  let stageCwd: string | undefined = cwd;
  const cwdStack: Array<string | undefined> = [];
  const decoded: string[] = [];
  for (const { words: rawStage, separator } of stages) {
    const currentCwd: string = stageCwd ?? cwd;
    const projectedContent = separator === ")" && (rawStage.length === 0 || /^\.Content$/iu.test(rawStage[0] ?? ""));
    downloadStream &&= (rawStage.length > 0 && separator === "|") || projectedContent;
    let stage = rawStage.slice();
    while (stage.length > 0) {
      const first = stage[0]!;
      const cleanVerb = basename(unquoteShellWord(stripShellCarets(first)).replace(/\\/gu, "/")).replace(/\.(?:exe|cmd)$/iu, "").toLowerCase();
      if (((cleanVerb === "env" || /^\w+=.*$/u.test(first)) || /^(?:sudo|command|exec|nohup|time)$/iu.test(cleanVerb)) && stage.length > 1) {
        stage = stage.slice(1);
        continue;
      }
      if (cleanVerb === "cmd" && stage.length >= 3 && /^\/[ck]$/iu.test(stripShellCarets(stage[1]!))) {
        const rest = stage.slice(2);
        if (rest.length === 1 && /^["'][\s\S]*["']$/u.test(rest[0]!)) {
          const nested = analyzeShellCommand(unquoteShellWord(rest[0]!).replace(/\^/gu, ""), decode, currentCwd);
          urls.push(...nested.urls);
          hosts.push(...nested.hosts);
          redirectTargets.push(...nested.redirectTargets);
          readTargets.push(...nested.readTargets);
          if (stageCwd !== undefined) {
            downloads.push(...nested.downloads);
            copies.push(...nested.copies);
          }
          pathOperands.push(...nested.pathOperands);
          executionOperands.push(...nested.executionOperands);
          scriptFiles.push(...nested.scriptFiles);
          sensitiveRead ||= nested.sensitiveRead;
          if (nested.external) external = true;
          if (nested.decodedCommand) decoded.push(nested.decodedCommand);
          nestedSuspicious.push(...nested.suspicious);
          stage = [];
          break;
        }
        stage = rest.map(stripShellCarets);
        continue;
      }
      break;
    }
    const [head, ...words] = stage;
    if (!head) continue;
    const verb = basename(unquoteShellWord(stripShellCarets(head)).replace(/\\/gu, "/")).replace(/\.(?:exe|cmd)$/iu, "");
    const stageVerb = verb.toLowerCase();
    const transferVerb = /^(?:curl|wget)$/u.test(stageVerb) || WEB_REQUEST.test(stageVerb);
    downloadStream ||= transferVerb;
    const args: string[] = [];
    const pathFromStage = (path: string) => currentCwd === cwd ? path : resolveHookPath(path, currentCwd).logical;
    for (let i = 0; i < words.length; i++) {
      const word = words[i]!;
      if (/^(?:[12]?>>?|<)$/u.test(word)) {
        const target = words[++i];
        if (target) {
          const path = unquoteShellWord(target);
          (word === "<" ? readTargets : redirectTargets).push(pathFromStage(path));
          if (stageCwd !== undefined && downloadStream && /^1?>>?$/u.test(word)) downloads.push({ path, cwd: currentCwd });
        }
      } else {
        args.push(word);
      }
    }
    const lowerArgs = args.map((word) => stripShellCarets(unquoteShellWord(word)));
    const operands = [unquoteShellWord(head), ...lowerArgs.map((arg) =>
      arg.replace(/^--?[\w-]+[=:]/u, "").replace(/^@/u, ""))].filter((arg) => arg && !arg.startsWith("-") && arg !== ",");
    const paths = TEXT_OUTPUT.test(stageVerb)
      ? operands.filter((arg, index) => index === 0 || !/\s/u.test(arg) || /[\\/]/u.test(arg) || SENSITIVE_FILE.test(arg))
      : operands;
    pathOperands.push(...paths.map(pathFromStage));
    const stageCopies = stageCwd !== undefined && COPY_COMMAND.test(stageVerb) ? shellFileCopies(stageVerb, lowerArgs, currentCwd) : [];
    copies.push(...stageCopies);
    downloads.push(...stageCopies);
    if (stageCopies.length === 0 && !LOCATION_COMMAND.test(stageVerb)) executionOperands.push(...operands);
    let gitSubcommand = "";
    let gitSubcommandIndex = -1;
    let gitCwd = currentCwd;
    const gitDirs: string[] = [];
    if (/^git$/iu.test(verb)) {
      for (let i = 0; i < lowerArgs.length; i++) {
        const arg = lowerArgs[i]!;
        if (arg === "-C" || arg === "--git-dir" || arg === "--work-tree") {
          if (lowerArgs[i + 1]) {
            const dir = lowerArgs[++i]!;
            gitDirs.push(dir);
            if (arg === "-C") gitCwd = resolveHookPath(dir, gitCwd).logical;
          }
          continue;
        }
        if (arg === "-c") { i++; continue; }
        if (/^--(?:git-dir|work-tree)=(.+)$/iu.test(arg)) {
          gitDirs.push(arg.split(/=(.*)/u)[1]!);
          continue;
        }
        if (/^-C(.+)$/iu.test(arg)) {
          gitDirs.push(arg.slice(2));
          gitCwd = resolveHookPath(arg.slice(2), gitCwd).logical;
          continue;
        }
        if (arg.startsWith("-")) continue;
        gitSubcommand = arg;
        gitSubcommandIndex = i;
        break;
      }
    }
    const subcommand = /^git$/iu.test(verb) ? gitSubcommand : (lowerArgs[0] ?? "");
    const nextArg = lowerArgs[1]?.toLowerCase();
    const scriptHead = unquoteShellWord(head);
    if (/\.(?:bat|cmd|ps1|sh)$/iu.test(scriptHead) || /^\.[\\/]/u.test(scriptHead)) {
      scriptFiles.push(scriptHead);
    } else if (SCRIPT_INTERPRETER.test(stageVerb) || PYTHON_COMMAND.test(stageVerb) || POWERSHELL_COMMAND.test(stageVerb)) {
      const scriptIndex = lowerArgs.findIndex((arg) => arg === "-" || !arg.startsWith("-"));
      const script = lowerArgs[scriptIndex];
      if (script && script !== "-" && !(PYTHON_COMMAND.test(stageVerb) && lowerArgs[scriptIndex - 1] === "-m")) scriptFiles.push(script);
    } else if (/^(?:npm|pnpm|yarn|bun)$/u.test(stageVerb) && /^(?:run|run-script|test|start)$/iu.test(subcommand)) {
      scriptFiles.push("package.json");
    } else if (stageVerb === "make") {
      const makefile = lowerArgs.findIndex((arg) => /^(?:-f|--file|--makefile)(?:=|$)/u.test(arg));
      scriptFiles.push(makefile < 0 ? "Makefile" : lowerArgs[makefile]!.split("=")[1] || lowerArgs[makefile + 1] || "Makefile");
    }
    const gitRemote = /^git$/iu.test(verb) && (
      /^(?:fetch|pull|clone|ls-remote|submodule)$/iu.test(gitSubcommand)
      || (/^(?:log|show)$/iu.test(gitSubcommand) && gitSubcommandIndex >= 0 && referencesRemoteGitRef(lowerArgs, gitSubcommandIndex + 1, currentCwd))
    );
    const network = NETWORK_COMMAND.test(verb) || (gitRemote && /^clone$/iu.test(gitSubcommand));
    const tar = stageVerb === "tar" ? tarArguments(lowerArgs) : undefined;
    const archive = archiveExtraction(stageVerb, lowerArgs, currentCwd, tar);
    if (archive && stageCwd !== undefined) downloads.push(archive);
    const archiveSources = tar ? (tar.pack ? tar.inputs : []) : archiveInputs(stageVerb, lowerArgs);
    sensitiveRead ||= stageVerb === "printenv"
      || (stageVerb === "env" || stageVerb === "set") && lowerArgs.length === 0
      || lowerArgs.length === 1 && (stageVerb === "export" && subcommand === "-p" || stageVerb === "declare" && subcommand === "-x")
      || stageVerb === "git" && /^config$/iu.test(subcommand) && lowerArgs.slice(gitSubcommandIndex + 1).some((arg) => arg === "--list" || arg === "-l")
      || /^(?:get-childitem|gci|dir|ls|get-item|gi)$/u.test(stageVerb) && lowerArgs.some((arg) => /^(?:-(?:path|literalpath):)?\$?env:/iu.test(arg))
      || archiveSources.some((source) => {
        const path = source.replace(/\\/gu, "/");
        return /^\.\/?$/u.test(path) || relative(cwd, resolve(currentCwd, path)) === ""
          || /(?:^|\/)\.(?:git|claude|palizade)(?:\/|$)/iu.test(path)
          || basename(path) === "*" && relative(cwd, resolve(currentCwd, dirname(path))) === "";
      });
    const submodule = gitSubcommand.toLowerCase() === "submodule" && lowerArgs[gitSubcommandIndex + 1]?.toLowerCase() === "add";
    const ghClone = stageVerb === "gh" && subcommand.toLowerCase() === "repo" && lowerArgs[1]?.toLowerCase() === "clone";
    if (submodule || ghClone || (gitRemote && /^clone$/iu.test(gitSubcommand))) {
      const cloneArgs = lowerArgs.slice(ghClone ? 2 : gitSubcommandIndex + (submodule ? 2 : 1));
      const ghOptions = ghClone ? cloneArgs.indexOf("--") : -1;
      const path = clonePath(ghOptions === -1 ? cloneArgs : cloneArgs.slice(0, ghOptions), submodule);
      if (path && stageCwd !== undefined) downloads.push({ path, cwd: gitCwd, directory: true });
    }
    let cdExternal = false;
    if (LOCATION_COMMAND.test(stageVerb)) {
      const [dir] = shellFileArguments(args, true);
      if (stageVerb.startsWith("pop")) stageCwd = cwdStack.pop();
      else {
        if (stageVerb.startsWith("push")) cwdStack.push(stageCwd);
        const target = dir && dir !== "-" && !DYNAMIC_PATH.test(dir) && (stageCwd !== undefined || isAbsolute(dir)) && resolveHookPath(dir, currentCwd);
        stageCwd = target && !target.uncertain ? target.logical : undefined;
      }
      cdExternal = stageCwd === undefined || externalFile(stageCwd, cwd);
      if (separator === "|") stageCwd = currentCwd;
    }
    const gitExternal = /^git$/iu.test(verb) && gitDirs.some((dir) => externalFile(dir, currentCwd));
    const containerLogExternal = (/^docker$/iu.test(verb) && shellToolSubcommand(lowerArgs, DOCKER_VALUE_FLAGS) === "logs")
      || (/^kubectl$/iu.test(verb) && shellToolSubcommand(lowerArgs, KUBECTL_VALUE_FLAGS) === "logs");
    const pmExternal = /^(?:npx|bunx)$/iu.test(verb)
      || (/^(?:pnpm|yarn)$/iu.test(verb) && /^dlx$/iu.test(subcommand))
      || (/^(?:npm|pnpm|yarn|bun)$/iu.test(verb) && (/^(?:install|i|add|ci|up|update)$/iu.test(subcommand) || (/^npm$/iu.test(verb) && /^(?:view|info)$/iu.test(subcommand))))
      || (/^(?:pip|pip3)$/iu.test(verb) && /^(?:install|download)$/iu.test(subcommand))
      || (stageVerb === "uv" && (subcommand === "install" || (subcommand === "pip" && nextArg === "install")))
      || stageVerb === "uvx"
      || (/^(?:npm|pnpm|yarn|bun)$/u.test(stageVerb) && /^exec$/iu.test(subcommand))
      || (PYTHON_COMMAND.test(stageVerb) && subcommand === "-m" && nextArg === "pip")
      || (stageVerb === "pipx" && /^(?:run|install)$/iu.test(subcommand))
      || (/^(?:cargo|gem|brew|choco|winget|scoop)$/u.test(stageVerb) && /^install$/iu.test(subcommand))
      || (stageVerb === "go" && /^(?:run|install|get)$/iu.test(subcommand) && lowerArgs.slice(1).some((arg) => /^[^-].*@.+$/u.test(arg)))
      || (stageVerb === "dotnet" && /^tool$/iu.test(subcommand) && nextArg === "install")
      || (stageVerb === "composer" && /^require$/iu.test(subcommand))
      || (/^(?:npm|pnpm|yarn|bun)$/u.test(stageVerb) && /^create$/iu.test(subcommand))
      || (/^(?:npm|bun)$/u.test(stageVerb) && /^x$/iu.test(subcommand))
      || (stageVerb === "npm" && /^init$/iu.test(subcommand) && lowerArgs.slice(1).some((arg, index) =>
        arg && !arg.startsWith("-") && !NPM_INIT_VALUE_FLAG.test(lowerArgs[index]!)))
      || (stageVerb === "yarn" && /^global$/iu.test(subcommand) && nextArg === "add")
      || (stageVerb === "corepack" && /^(?:npm|pnpm|yarn)@.+$/iu.test(subcommand))
      || (stageVerb === "uv" && (subcommand === "add" || subcommand === "tool" && /^(?:run|install)$/u.test(nextArg ?? "")))
      || (PYTHON_COMMAND.test(stageVerb) && lowerArgs.some((arg, index) => arg === "-m" && lowerArgs[index + 1]?.toLowerCase() === "pip"))
      || (/^pip3\.\d+$/u.test(stageVerb) && /^(?:install|download)$/iu.test(subcommand))
      || (/^(?:conda|mamba|apt|apt-get|dnf|yum)$/u.test(stageVerb) && /^install$/iu.test(subcommand))
      || (/^(?:poetry|pdm)$/u.test(stageVerb) && /^add$/iu.test(subcommand))
      || (stageVerb === "pacman" && /^-S[a-z]*$/u.test(subcommand))
      || /^install-(?:module|package|script)$/u.test(stageVerb);
    const inlineExternal = (/^python(?:3(?:\.\d+)?)?$/iu.test(verb) && lowerArgs.includes("-c"))
      || (/^(?:node|perl|ruby)$/iu.test(verb) && lowerArgs.some((arg) => arg === "-e" || arg === "--eval"));
    external ||= network || gitRemote || REMOTE_COMMAND.test(verb) || cdExternal || gitExternal || containerLogExternal || pmExternal || inlineExternal;
    if (network) {
      const transfer = transferVerb ? transferArguments(stageVerb, lowerArgs) : undefined;
      if (transfer && stageCwd !== undefined) downloads.push(...transfer.outputs.map((path) => ({ path, cwd: currentCwd })));
      const remotePathOnly = /^(?:scp|rsync)$/u.test(stageVerb);
      for (const word of transfer?.operands ?? lowerArgs) {
        const cleaned = word.replace(/^-(?:uri|computername|name|source):/iu, "");
        const uri = /^[a-z][a-z\d+.-]*:\/\//iu.test(cleaned) ? URL.parse(cleaned) : null;
        const scpMatch = /^(?:[a-z0-9._-]+@)?(\[[\da-f:.]+\]|[\p{L}\p{N}][\p{L}\p{N}.-]*):/iu.exec(cleaned);
        const drivePath = process.platform === "win32" && /^[a-z]:/iu.test(cleaned);
        const host = (uri?.hostname ? canonicalHost(uri.hostname) : undefined)
          || (!remotePathOnly ? parseShellHost(cleaned) : undefined)
          || (scpMatch && !drivePath ? canonicalHost(scpMatch[1]!) : undefined);
        if (host) hosts.push(host);
      }
    }
    for (let i = 0; i < args.length; i++) {
      const cleaned = unquoteShellWord(args[i]!);
      if (network) {
        if (cleaned.startsWith("@") && cleaned.length > 1 && cleaned !== "@-") {
          const target = cleaned.slice(1).split(";", 1)[0]!;
          if (target) readTargets.push(pathFromStage(target));
        } else {
          const attached = /(?:^[^=]+=@|^-(?:d|-data(?:-[a-z-]+)?|F|-form(?:-string)?)@)([^;\s"']+)/iu.exec(cleaned);
          if (attached?.[1] && attached[1] !== "-") readTargets.push(pathFromStage(attached[1]));
        }
        if (/^(?:-T|--upload-file)$/iu.test(cleaned) && args[i + 1]) {
          readTargets.push(pathFromStage(unquoteShellWord(args[i + 1]!)));
        } else {
          const upload = /^--upload-file=(.+)$/iu.exec(cleaned);
          if (upload?.[1]) readTargets.push(pathFromStage(unquoteShellWord(upload[1])));
        }
      }
      if (/^-InFile$/iu.test(cleaned) && args[i + 1]) {
        readTargets.push(pathFromStage(unquoteShellWord(args[i + 1]!)));
      } else {
        const inFile = /^-InFile:(.+)$/iu.exec(cleaned);
        if (inFile?.[1]) readTargets.push(pathFromStage(unquoteShellWord(inFile[1])));
      }
    }
    if (FILE_READER.test(verb)) readTargets.push(...shellFileArguments(args, false, PATTERN_FIRST_READER.test(verb)).map(pathFromStage));
    if (FILE_WRITER.test(verb)) redirectTargets.push(...shellFileArguments(args, true).map(pathFromStage));
    if (downloadStream && separator === "|" && stageCwd !== undefined && (stageVerb === "tee" || FILE_WRITER.test(verb))) {
      const targets = stageVerb === "tee" ? shellFileArguments(args) : shellFileArguments(args, true);
      downloads.push(...targets.map((path) => ({ path, cwd: currentCwd })));
    }
    if (decode && /^(?:powershell|pwsh)$/iu.test(stripShellCarets(verb))) {
      const flag = args.findIndex(isEncodedCommandFlag);
      const flagWord = flag >= 0 ? stripShellCarets(unquoteShellWord(args[flag]!)) : "";
      const inlineValue = flagWord.includes(":") ? flagWord.split(/:(.*)/u)[1] : undefined;
      const value = flag < 0 ? "" : (inlineValue || unquoteShellWord(args[flag + 1] ?? ""));
      if (/^[a-z\d+/]+={0,2}$/iu.test(value) && value.length % 4 !== 1) {
        try { decoded.push(new TextDecoder("utf-16le", { fatal: true }).decode(Buffer.from(value, "base64"))); }
        catch { /* An invalid payload has no command to inspect. */ }
      }
    }
  }
  for (const url of urls) {
    try { hosts.push(canonicalHost(new URL(url).hostname)); } catch { /* Keep the URL as a separate argument. */ }
  }
  if (netClient) {
    for (const word of command.match(/["'][^"']+["']/gu) ?? []) {
      const host = parseShellHost(word);
      if (host) hosts.push(host);
    }
  }
  const decodedCommand = decoded.join("\n");
  const inner = decodedCommand ? analyzeShellCommand(decodedCommand, false, cwd) : undefined;
  const suspicious = [
    ...(suspiciousShell(command) ? ["shell-suspicious-construct"] : []),
    ...nestedSuspicious,
    ...(inner?.suspicious ?? [])
  ];
  external ||= urls.length > 0 || hosts.length > 0 || Boolean(inner?.external);
  return {
    commandName,
    urls: [...new Set([...urls, ...inner?.urls ?? []])],
    hosts: [...new Set([...hosts, ...inner?.hosts ?? []])],
    redirectTargets: [...new Set([...redirectTargets, ...inner?.redirectTargets ?? []])],
    readTargets: [...new Set([...readTargets, ...inner?.readTargets ?? []])],
    downloads: [...downloads, ...inner?.downloads ?? []],
    copies: [...copies, ...inner?.copies ?? []],
    pathOperands: [...pathOperands, ...inner?.pathOperands ?? []],
    executionOperands: [...executionOperands, ...inner?.executionOperands ?? []],
    scriptFiles: [...new Set([...scriptFiles, ...inner?.scriptFiles ?? []])],
    sensitiveRead: sensitiveRead || Boolean(inner?.sensitiveRead),
    external,
    ...(decodedCommand ? { decodedCommand } : {}),
    suspicious: [...new Set(suspicious)]
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
    const tool = String(record.tool_name ?? "unknown");
    if (event === "PreToolUse") {
      return { kind: "pre", tool, input: normalizeToolInput(toolInput, tool) };
    }
    if (event === "PostToolUse") {
      return { kind: "post", tool, input: normalizeToolInput(toolInput, tool), response: record.tool_response };
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

  if (client === "gemini") {
    const tool = String(record.tool_name ?? "unknown");
    if (event === "BeforeTool") return { kind: "pre", tool, input: normalizeToolInput(toolInput, tool) };
    if (event === "AfterTool") {
      // tool_response is { llmContent, returnDisplay, error? }; llmContent is what the model reads.
      const response = record.tool_response && typeof record.tool_response === "object" ? record.tool_response as Record<string, unknown> : {};
      const content = response.llmContent;
      return {
        kind: "post",
        tool,
        input: normalizeToolInput(toolInput, tool),
        response: typeof content === "string" ? { content: [{ type: "text", text: content }] } : content ?? response
      };
    }
    return undefined;
  }

  if (client === "codex") {
    const tool = String(record.tool_name ?? "unknown");
    if (event === "PreToolUse") {
      return { kind: "pre", tool, input: normalizeToolInput(toolInput, tool) };
    }
    if (event === "PostToolUse") {
      return { kind: "post", tool, input: normalizeToolInput(toolInput, tool), response: record.tool_response };
    }
    return undefined;
  }

  return undefined;
}

/**
 * Gemini CLI names MCP tools `mcp_<server>_<tool>` with single underscores, so the server is the
 * longest configured name (in ~/.gemini/settings.json or the project's .gemini/settings.json)
 * that fits.
 */
export function parseGeminiMcpToolName(tool: string, cwd: string, home = homedir()): { server: string; tool: string; entry: ClientServerEntry } | undefined {
  if (!tool.startsWith("mcp_")) return undefined;
  const servers: Record<string, ClientServerEntry & { httpUrl?: string }> = {};
  for (const path of [join(home, ".gemini", "settings.json"), join(cwd, ".gemini", "settings.json")]) {
    try {
      if (existsSync(path)) Object.assign(servers, (JSON.parse(readFileSync(path, "utf8")) as { mcpServers?: Record<string, ClientServerEntry> }).mcpServers ?? {});
    } catch {
      // An unreadable settings file only means the server is not recognized.
    }
  }
  const name = Object.keys(servers).filter((candidate) => tool.startsWith(`mcp_${candidate}_`)).sort((a, b) => b.length - a.length)[0];
  if (!name) return undefined;
  const raw = servers[name]!;
  return { server: name, tool: tool.slice(`mcp_${name}_`.length), entry: { ...(raw.command ? { command: raw.command } : {}), ...(raw.args ? { args: raw.args } : {}), ...(raw.url ?? raw.httpUrl ? { url: raw.url ?? raw.httpUrl } : {}) } };
}

/** `mcp__<server>__<tool>`, the name Claude Code and Codex give MCP tools in hooks. */
export function parseMcpToolName(tool: string): { server: string; tool: string } | undefined {
  const match = /^mcp__(.+?)__(.+)$/u.exec(tool);
  return match ? { server: match[1]!, tool: match[2]! } : undefined;
}

export type ClientServerEntry = { command?: string; args?: string[]; url?: string };

/**
 * Finds how the client itself launches an MCP server (command or url), so the tool catalog can
 * recognize it. Claude Code: ~/.claude.json (user and local scope) and .mcp.json in the project.
 */
export function findClientServerEntry(serverName: string, cwd: string, home = homedir(), source?: string): ClientServerEntry | undefined {
  const read = (path: string): Record<string, unknown> | undefined => {
    try { return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown> : undefined; } catch { return undefined; }
  };
  const pick = (servers: unknown): ClientServerEntry | undefined => {
    const entry = servers && typeof servers === "object" && Object.hasOwn(servers, serverName) ? (servers as Record<string, unknown>)[serverName] : undefined;
    if (!entry || typeof entry !== "object") return undefined;
    const record = entry as Record<string, unknown>;
    return {
      ...(typeof record.command === "string" ? { command: record.command } : {}),
      ...(Array.isArray(record.args) ? { args: record.args.filter((arg): arg is string => typeof arg === "string") } : {}),
      ...(typeof record.url === "string" ? { url: record.url } : {})
    };
  };
  const project = () => pick(read(join(cwd, ".mcp.json"))?.mcpServers);
  if (source === "project") return project();
  if (source !== undefined && source !== "local" && source !== "user") return undefined;
  const user = read(join(home, ".claude.json"));
  const projects = user?.projects && typeof user.projects === "object" ? user.projects as Record<string, { mcpServers?: unknown }> : {};
  const canonicalPath = (path: string) => process.platform === "win32" ? path.replaceAll("\\", "/").toLowerCase() : path;
  const projectKey = Object.keys(projects).find((path) => canonicalPath(path) === canonicalPath(cwd));
  const local = () => pick(projectKey ? projects[projectKey]?.mcpServers : undefined);
  if (source === "local") return local();
  if (source === "user") return pick(user?.mcpServers);
  return project() ?? local() ?? pick(user?.mcpServers);
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
  const url = typeof payload.url === "string" ? payload.url : typeof payload.mcp_server_url === "string" ? payload.mcp_server_url : undefined;
  // Current Cursor sends mcp_server_name, plus url (HTTP) or the launch command (stdio).
  const named = typeof payload.mcp_server_name === "string" ? payload.mcp_server_name : undefined;
  if (named) {
    const registered = Object.hasOwn(servers, named) ? servers[named] : undefined;
    if (url) return { key: named, entry: { url } };
    if (command && command !== named && command !== [registered?.command, ...(registered?.args ?? [])].join(" ")) {
      const [exe, ...args] = command.split(" ");
      return { key: named, entry: { command: exe!, args } };
    }
    const entry = registered ?? {};
    return { key: named, entry };
  }
  if (command && Object.hasOwn(servers, command)) return { key: command, entry: servers[command]! };
  for (const [key, entry] of Object.entries(servers)) {
    if (url && entry.url === url) return { key, entry };
    if (command && [entry.command, ...(entry.args ?? [])].filter(Boolean).join(" ") === command) return { key, entry };
  }
  return undefined;
}

/** Confirms the client entry launches this Palizade CLI and a server from the selected config. */
export function isRegisteredPalizadeWrapper(entry: ClientServerEntry | undefined, config: PalizadeConfig, configPath: string, cliPath: string): boolean {
  if (entry?.url || typeof entry?.command !== "string" || !Array.isArray(entry.args) || entry.args.length !== 5) return false;
  const [script, subcommand, server, configFlag, wrapperConfig] = entry.args;
  if (subcommand !== "wrap" || configFlag !== "-c" || !server || !Object.hasOwn(config.servers, server)) return false;
  const samePath = (left: string | undefined, right: string): boolean => {
    if (typeof left !== "string" || !isAbsolute(left) || !isAbsolute(right)) return false;
    try {
      const normalize = (path: string) => process.platform === "win32" ? path.toLowerCase() : path;
      return normalize(realpathSync(left)) === normalize(realpathSync(right));
    } catch {
      return false;
    }
  };
  return samePath(entry.command, process.execPath) && samePath(script, cliPath) && samePath(wrapperConfig, configPath);
}

/**
 * The engine target for an MCP tool seen through a hook. A server already wrapped by Palizade is
 * checked by its proxy, so the hook stands aside; anything else (remote servers that sign in with
 * OAuth, servers the user did not wrap) is checked here as an untrusted server, recognized by the
 * catalog from the client's own config when possible.
 */
function mcpHookTarget(config: PalizadeConfig, serverName: string, cwd: string, entry?: ClientServerEntry): { serverName: string; server: ServerConfig } {
  const server = serverConfigSchema.parse({
    ...(entry?.url ? { url: entry.url } : { command: entry?.command ?? `mcp:${serverName}`, args: entry?.args ?? [] }),
    trust: config.hooks.mcpTrust,
    cwd
  });
  return { serverName, server };
}

function extractApplyPatchPaths(text: string): string[] {
  const paths: string[] = [];
  for (const match of text.matchAll(/^\*\*\*\s+(?:Update File|Add File|Delete File|Move to):\s*(.+)$/gmu)) {
    const candidate = match[1]?.trim();
    if (candidate) paths.push(candidate);
  }
  return [...new Set(paths)];
}

function normalizeToolInput(toolInput: unknown, tool?: string): Record<string, unknown> {
  if (tool === "apply_patch") {
    if (typeof toolInput === "string") {
      const file_paths = extractApplyPatchPaths(toolInput);
      return file_paths.length > 0 ? { patch: toolInput, file_paths } : { patch: toolInput };
    }
    if (toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)) {
      const obj = toolInput as Record<string, unknown>;
      if (typeof obj.file_path !== "string" && typeof obj.path !== "string" && !Array.isArray(obj.file_paths)) {
        const rawPatch = [obj.patch, obj.input, obj.diff, obj.content, obj.command].find((value): value is string => typeof value === "string");
        const file_paths = rawPatch ? extractApplyPatchPaths(rawPatch) : [];
        if (file_paths.length > 0) return { ...obj, file_paths };
      }
      return obj;
    }
  }
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

function enrichToolArguments(normalized: NormalizedNativeEvent, analysis: ShellAnalysis | undefined): Record<string, unknown> {
  const input: Record<string, unknown> = { ...normalized.input };
  if (analysis) {
    if (analysis.urls.length > 0) input.urls = analysis.urls;
    if (analysis.hosts.length > 0) input.hosts = analysis.hosts;
    if (analysis.redirectTargets.length > 0) input.redirectTargets = analysis.redirectTargets;
    if (analysis.decodedCommand !== undefined) input.decodedCommand = analysis.decodedCommand;
    if (analysis.suspicious.length > 0) input.suspiciousPatterns = analysis.suspicious;
  }
  return input;
}

function resolveHookPath(path: string, cwd: string): ReturnType<typeof resolveArgumentPath> {
  try { return resolveArgumentPath(path, cwd); }
  catch { return { logical: path, canonical: path, uncertain: true }; }
}

const SENSITIVE_FILE = /(?:^|[\\/])(?:\.env[^\\/]*$|\.(?:ssh|aws|kube)(?:[\\/]|$)|kube[\\/]config$|\.(?:npmrc|netrc|git-credentials)$|credentials\.json$)|\.(?:pem|key|pfx|p12)$/iu;
const COPIED_COMMAND_SENSITIVE_FILE = /(?:^|[\\/])(?:config[\\/]database\.yml|\.pgpass|(?:secrets\.|credentials|id_rsa)[^\\/]*)$|\.(?:secret|kdbx)$/iu;
const EXAMPLE_SAMPLE_FILE = /\.(?:example|sample)$/iu;
const DEPENDENCY_FILE = /(?:^|[\\/])node_modules(?:[\\/]|$)/iu;
const WORKSPACE_READ_TOOLS = new Set(["Read", "Grep", "Glob", "grep_search", "glob", "list_directory", "read_file", "read_many_files"]);
const WORKSPACE_PATH_OPTIONAL_TOOLS = new Set(["Grep", "Glob", "grep_search", "glob", "list_directory"]);
const WORKSPACE_LISTING_TOOLS = new Set(["Glob", "glob", "list_directory"]);

function sensitiveFile(path: string, cwd: string): boolean {
  const resolved = resolveHookPath(path, cwd);
  const matches = (candidate: string) =>
    !EXAMPLE_SAMPLE_FILE.test(basename(candidate))
      && (SENSITIVE_FILE.test(candidate) || COPIED_COMMAND_SENSITIVE_FILE.test(candidate));
  return matches(resolved.logical) || matches(resolved.canonical);
}

function externalFile(path: string, cwd: string): boolean {
  const resolved = resolveHookPath(path, cwd);
  return /[$*?]|^%[^%]+%|^[a-z]:[^\\/]|^\w+::/iu.test(path) ||
    !isWorkspacePath(resolved, cwd) || DEPENDENCY_FILE.test(resolved.logical) || DEPENDENCY_FILE.test(resolved.canonical);
}

const MAX_DOWNLOADED_PATHS = 64;

function downloadedPathKey(store: SqliteTaintStore, canonical: string, directory: boolean): string {
  const path = process.platform === "win32" || process.platform === "darwin" ? canonical.toLowerCase() : canonical;
  return store.destinationKey(`download:${directory ? "directory" : "file"}:${path}`);
}

function isDownloadedPath(store: SqliteTaintStore, known: Pick<ReadonlySet<string>, "size" | "has">, path: string, cwd: string): boolean {
  if (known.size === 0) return false;
  const { canonical, uncertain } = resolveHookPath(path, cwd);
  if (uncertain) return false;
  if (known.has(downloadedPathKey(store, canonical, false))) return true;
  for (let dir = canonical; ; dir = dirname(dir)) {
    if (known.has(downloadedPathKey(store, dir, true))) return true;
    if (dirname(dir) === dir) return false;
  }
}

function recordDownloads(store: SqliteTaintStore, sessionId: string, downloads: ShellDownload[], workspace: string, ttlMs: number): void {
  store.updateSession(sessionId, (state) => {
    const now = Date.now();
    const keys = new Map((state.downloadedPaths ?? []).filter((entry) => entry.expiresAt > now).map(({ key, expiresAt }) => [key, expiresAt]));
    for (const { path, cwd, directory, source } of downloads) {
      if (DYNAMIC_PATH.test(path) || path === "-" || DOS_DEVICE_NAME_RE.test(basename(path))) continue;
      const target = resolveHookPath(path, cwd);
      if (!isWorkspacePath(target, workspace) || (source && !isDownloadedPath(store, keys, source, cwd))) continue;
      const key = downloadedPathKey(store, target.canonical, directory === true);
      keys.delete(key);
      keys.set(key, now + ttlMs);
      if (keys.size > MAX_DOWNLOADED_PATHS) keys.delete(keys.keys().next().value!);
    }
    return { ...state, downloadedPaths: [...keys].map(([key, expiresAt]) => ({ key, expiresAt })) };
  });
}

const HOOK_TEXT_LIMIT = 64 * 1024;

function capHookText(text: string): string {
  if (Buffer.byteLength(text) <= HOOK_TEXT_LIMIT) return text;
  const bytes = Buffer.from(text);
  const half = HOOK_TEXT_LIMIT / 2 - 4; // Leave room for the separator and partial UTF-8 characters.
  return bytes.subarray(0, half).toString("utf8") + "\n" + bytes.subarray(-half).toString("utf8");
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function webSearchText(response: unknown): string {
  if (typeof response === "string") return response;
  const { results, query: _query, ...other } = recordValue(response);
  if (!Array.isArray(results)) return flattenArguments(other);
  const parts: string[] = [];
  for (const entry of results) {
    if (typeof entry === "string") {
      parts.push(entry);
      continue;
    }
    const result = recordValue(entry);
    if (!Array.isArray(result.content)) {
      for (const value of [result.title, result.url, result.content]) if (typeof value === "string") parts.push(value);
      continue;
    }
    for (const item of result.content) {
      const hit = recordValue(item);
      for (const value of [hit.title, hit.url]) if (typeof value === "string") parts.push(value);
    }
  }
  return parts.join("\n");
}

function normalizeSampledDestinations(raw: unknown, destinationOnly: boolean): string[] {
  if (!Array.isArray(raw)) return [];
  const candidates = raw
    .filter((item): item is string => typeof item === "string" && item.length > 0)
    .map((item) => {
      const stripped = item.replace(/^(?:url|email|host):/u, "");
      return isIP(stripped) === 6 ? `[${stripped}]` : stripped;
    });
  return candidates.length > 0 ? extractDestinationObservables(candidates.join("\n"), destinationOnly) : [];
}

interface HookInspectionResult {
  result: unknown;
  singleTextBlock?: boolean;
  agentResult?: { id: string | undefined; report: string };
  destinationOnly?: boolean;
  workspaceSource?: boolean;
  sensitivePath?: boolean;
  inspectionOnly?: boolean;
  truncated?: boolean;
  sampledDestinations?: string[];
}

function inspectHookResult(normalized: NormalizedNativeEvent, analysis: ShellAnalysis | undefined, cwd: string, readTaint: PalizadeConfig["hooks"]["readTaint"], downloaded: (path: string) => boolean): HookInspectionResult {
  const result = normalized.response;
  const response = recordValue(result);
  if (normalized.tool === "WebSearch") {
    const fullText = webSearchText(result);
    const capped = Buffer.byteLength(fullText) > HOOK_TEXT_LIMIT;
    const truncated = capped || isSubstringsTruncated(normalizeText(fullText));
    return {
      result: capHookText(fullText),
      singleTextBlock: true,
      ...(truncated ? { truncated: true } : {}),
      ...(capped ? { sampledDestinations: extractDestinationObservables(fullText) } : {})
    };
  }
  if (normalized.tool === "Agent") {
    const { content, agentId, agentType, toolsUsed, harnessNoteCount } = response;
    const parts = (Array.isArray(content) ? content.map((part) => recordValue(part).text) : [])
      .filter((part): part is string => typeof part === "string");
    const destinationOnly = agentType !== "web-fetch" && Array.isArray(toolsUsed) && toolsUsed.every((tool) =>
      typeof tool === "string" && !UNTRUSTED_AGENT_TOOLS.has(tool) && !tool.startsWith("mcp__"));
    const fullText = parts.join("\n");
    const resultText = capHookText(fullText);
    const expectedHeader = Array.isArray(toolsUsed) ? `<tools-used-before-summary>${toolsUsed.join(", ")}</tools-used-before-summary>` : undefined;
    let reportParts = [...parts];
    if (expectedHeader !== undefined && reportParts.length > 1 && reportParts[0]!.trim() === expectedHeader) {
      reportParts = reportParts.slice(1);
    }
    const maxNotes = typeof harnessNoteCount === "number" && Number.isInteger(harnessNoteCount) && harnessNoteCount > 0 ? harnessNoteCount : 0;
    let strippedNotes = 0;
    while (strippedNotes < maxNotes && reportParts.length > 1 && reportParts.at(-1)!.startsWith("[Harness note, not part of the agent's report:")) {
      reportParts.pop();
      strippedNotes++;
    }
    const reportFull = reportParts.join("\n");
    const report = capHookText(reportFull);
    const capped = Buffer.byteLength(fullText) > HOOK_TEXT_LIMIT || Buffer.byteLength(reportFull) > HOOK_TEXT_LIMIT;
    const truncated = !destinationOnly && (capped || isSubstringsTruncated(normalizeText(fullText)) || isSubstringsTruncated(normalizeText(reportFull)));
    const sampledDestinations = capped
      ? [...new Set([...extractDestinationObservables(fullText, destinationOnly), ...extractDestinationObservables(reportFull, destinationOnly)])]
      : undefined;
    return {
      result: resultText,
      singleTextBlock: true,
      agentResult: { id: typeof agentId === "string" ? agentId : undefined, report },
      destinationOnly,
      workspaceSource: destinationOnly,
      ...(truncated ? { truncated: true } : {}),
      ...(sampledDestinations && sampledDestinations.length > 0 ? { sampledDestinations } : {})
    };
  }
  if (WORKSPACE_READ_TOOLS.has(normalized.tool)) {
    const file = recordValue(response.file);
    const inputPaths = [
      normalized.input.file_path,
      normalized.input.absolute_path,
      normalized.input.path,
      normalized.input.directory,
      normalized.input.dir,
      ...(Array.isArray(normalized.input.paths) ? normalized.input.paths : []),
      file.filePath
    ].filter((path): path is string => typeof path === "string" && path.length > 0);
    const basePaths = inputPaths.length === 0 && WORKSPACE_PATH_OPTIONAL_TOOLS.has(normalized.tool) ? [cwd] : inputPaths;
    const responseFiles = Array.isArray(response.filenames)
      ? response.filenames.filter((path): path is string => typeof path === "string" && path.length > 0)
      : [];
    const grepPaths = normalized.tool === "Grep" && typeof response.content === "string"
      ? Array.from(capHookText(response.content).matchAll(/^((?:[a-z]:)?[^:\r\n]+):/gimu), (match) => match[1]!) : [];
    const externalCheckPaths = [...basePaths, ...responseFiles];
    const sensitiveCheckPaths = WORKSPACE_LISTING_TOOLS.has(normalized.tool) ? basePaths : externalCheckPaths;
    const sensitivePath = sensitiveCheckPaths.some((path) => sensitiveFile(path, cwd));
    const destinationOnly = readTaint !== "all" && !sensitivePath && externalCheckPaths.length > 0
      && externalCheckPaths.every((path) => !externalFile(path, cwd) && !downloaded(path))
      && !grepPaths.some(downloaded);
    const readPayload = normalized.tool === "Read" ? (typeof file.content === "string" ? file.content : file.cells ?? result) : result;
    const fullText = typeof readPayload === "string" ? readPayload : flattenArguments(readPayload);
    const capped = Buffer.byteLength(fullText) > HOOK_TEXT_LIMIT;
    const truncated = !destinationOnly && (capped || isSubstringsTruncated(normalizeText(fullText)));
    const sampledDestinations = capped ? extractDestinationObservables(fullText, destinationOnly) : undefined;
    return {
      result: normalized.tool === "Read"
        ? (typeof file.content === "string" ? file.content : file.cells ?? (capped ? capHookText(fullText) : result))
        : (capped ? capHookText(fullText) : result),
      ...(capped ? { singleTextBlock: true } : {}),
      destinationOnly,
      workspaceSource: destinationOnly,
      sensitivePath,
      ...(truncated ? { truncated: true } : {}),
      ...(sampledDestinations && sampledDestinations.length > 0 ? { sampledDestinations } : {})
    };
  }
  if (analysis) {
    const knownShellOutput = typeof response.stdout === "string" || typeof response.stderr === "string";
    const text = knownShellOutput ? [response.stdout, response.stderr].filter((part): part is string => typeof part === "string").join("\n") : flattenArguments(result);
    const capped = Buffer.byteLength(text) > HOOK_TEXT_LIMIT;
    const destinationOnly = readTaint !== "all" && !analysis.external && analysis.readTargets.every((path) => !externalFile(path, cwd) && !downloaded(path));
    const truncated = !destinationOnly && (capped || isSubstringsTruncated(normalizeText(text)));
    const sampledDestinations = capped ? extractDestinationObservables(text, destinationOnly) : undefined;
    return {
      result: capHookText(text),
      ...(capped ? { singleTextBlock: true } : {}),
      destinationOnly,
      workspaceSource: destinationOnly,
      sensitivePath: analysis.sensitiveRead || [...analysis.readTargets, ...analysis.redirectTargets].some((path) => sensitiveFile(path, cwd)),
      inspectionOnly: isSafeInspectionShellCommand(typeof normalized.input.command === "string" ? normalized.input.command : "", cwd),
      ...(truncated ? { truncated: true } : {}),
      ...(sampledDestinations && sampledDestinations.length > 0 ? { sampledDestinations } : {})
    };
  }
  if (normalized.tool === "WebFetch") {
    const fullText = typeof result === "string" ? result : flattenArguments(result);
    const capped = Buffer.byteLength(fullText) > HOOK_TEXT_LIMIT;
    const truncated = capped || isSubstringsTruncated(normalizeText(fullText));
    if (capped || truncated) {
      const sampledDestinations = capped ? extractDestinationObservables(fullText) : undefined;
      return {
        result: capped ? capHookText(fullText) : result,
        ...(capped ? { singleTextBlock: true } : {}),
        truncated: true,
        ...(sampledDestinations && sampledDestinations.length > 0 ? { sampledDestinations } : {})
      };
    }
  }
  return { result };
}

const PROMPT_EVENTS: Record<NativeClient, string> = {
  "claude-code": "UserPromptSubmit",
  codex: "UserPromptSubmit",
  cursor: "beforeSubmitPrompt",
  gemini: "BeforeAgent"
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
  sampling?: HookSamplingMetadata;
  sessionId?: string;
  cwd?: string;
  /** Used when neither cwd nor the payload names a directory; defaults to process.cwd(). */
  fallbackCwd?: string;
  configPath?: string;
  cliPath?: string;
  resolveCodexRegistration?: (name: string, cwd: string) => ClientServerEntry | undefined;
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
  const cwd = input.cwd ?? payloadField(input.payload, "cwd") ?? input.fallbackCwd ?? process.cwd();
  const sessionId = input.sessionId ?? payloadField(input.payload, "session_id", "conversation_id") ?? "native-session";

  let approvedPolicy: PolicyDocument | undefined;
  let sealed: { lockfile: LockfileStore; learnedEgress: LearnedEgress } | undefined;
  if (normalized.kind === "pre") {
    const { config } = input;
    const source = configSource(config);
    const configPath = input.configPath ?? source?.path;
    let drift: string[] = [];
    try {
      if (sealEnabled(config, configPath, cwd)) {
        if (!configPath || source?.path !== configPath) {
          drift = [sealPath(config, configPath, cwd)];
        } else {
          const raw = await readFile(config.policy);
          const sidecars = readSealSidecars(config);
          const loaded = { [configPath]: source.sha256, [config.policy]: createHash("sha256").update(raw).digest("hex"), ...sidecars.hashes };
          drift = sealDrift(config, [configPath, config.policy], loaded, true, cwd);
          if (drift.length === 0) {
            approvedPolicy = parsePolicy(raw.toString("utf8"), config.policy);
            sealed = {
              lockfile: new LockfileStore(config.lockfile, sidecars.lockBytes),
              learnedEgress: new LearnedEgress(config.egress.learnedFile, undefined, sidecars.learnedBytes)
            };
          }
        }
      }
    } catch {
      drift = ["seal.json"];
    }
    if (drift.length > 0) {
      const reason = `Palizade could not verify the configuration seal (${drift.map((file) => basename(file)).join(", ")}). An operator can run palizade seal after approving the files.`;
      return process.env.PALIZADE_SEAL_PATH === undefined
        ? buildAskOutput(input.client, input.event, reason)
        : buildDenyOutput(input.client, input.event, reason);
    }
  }

  const record = input.payload && typeof input.payload === "object" ? input.payload as Record<string, unknown> : {};
  const cursorServer = input.client === "cursor" && (input.event === "beforeMCPExecution" || input.event === "afterMCPExecution") ? cursorServerKey(record, cwd) : undefined;
  const gemini = input.client === "gemini" ? parseGeminiMcpToolName(normalized.tool, cwd) : undefined;
  const parsed = input.client === "cursor" ? undefined : input.client === "gemini" ? gemini : parseMcpToolName(normalized.tool);
  // Claude Code 2.1.274+ names the server in mcp_server; prefer it over splitting the tool name.
  const provenance = record.mcp_server && typeof record.mcp_server === "object" ? record.mcp_server as Record<string, unknown> : {};
  const declared = provenance.name;
  const mcp = input.client === "cursor"
    ? (cursorServer ? { server: cursorServer.key, tool: normalized.tool } : undefined)
    : parsed && typeof declared === "string" && normalized.tool.startsWith(`mcp__${declared}__`)
      ? { server: declared, tool: normalized.tool.slice(`mcp__${declared}__`.length) }
      : parsed;
  const claudeSource = typeof provenance.source === "string" && declared === mcp?.server ? provenance.source : undefined;
  const entry = !mcp ? undefined : input.client === "claude-code"
    ? findClientServerEntry(mcp.server, cwd, homedir(), claudeSource)
    : input.client === "codex" ? input.resolveCodexRegistration?.(mcp.server, cwd) : cursorServer?.entry ?? gemini?.entry;
  // Claude SDK/plugin servers can share a configured name. Delegate only with recognized native provenance.
  if (mcp && (input.client !== "claude-code" || claudeSource !== undefined) && input.configPath && input.cliPath &&
      isRegisteredPalizadeWrapper(entry, input.config, input.configPath, input.cliPath)) {
    return { exitCode: 0, output: undefined, reason: "MCP server is wrapped by Palizade; its proxy checks this call." };
  }
  const target = mcp ? mcpHookTarget(input.config, mcp.server, cwd, entry) : undefined;
  if (mcp) normalized.tool = mcp.tool;
  const command = normalized.input.command;
  const context = await createHookEngine(input.config, sessionId, cwd, [], target, approvedPolicy, sealed);
  try {
    const analysis = !mcp && SHELL_TOOLS.has(normalized.tool) && typeof command === "string"
      ? analyzeShellCommand(command, true, cwd)
      : undefined;
    return await withHookTimeout(input.config.hooks.timeoutMs, async () => {
      const id = `hook-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
      if (normalized.kind === "post") {
        const store = context.taintStore;
        if (analysis?.downloads.length) recordDownloads(store, sessionId, analysis.downloads, cwd, input.config.taint.exposure.ttlMs);
        const paths = !mcp && (analysis || WORKSPACE_READ_TOOLS.has(normalized.tool))
          ? new Set(store.getSession(sessionId).downloadedPaths?.filter((entry) => entry.expiresAt > Date.now()).map(({ key }) => key)) : undefined;
        const cliSampled = input.sampling?.sampled === true;
        const inspection: HookInspectionResult = mcp
          ? { result: normalized.response }
          : inspectHookResult(normalized, analysis, cwd, input.config.hooks.readTaint, (path) => paths !== undefined && isDownloadedPath(store, paths, path, cwd));
        const { result, sampledDestinations, ...restInspection } = inspection;
        const cliDestinations = normalizeSampledDestinations(input.sampling?.destinations, Boolean(inspection.destinationOnly));
        const allSampledDestinations = [...new Set([...(sampledDestinations ?? []), ...cliDestinations])];
        const toolUseId = payloadField(record, "tool_use_id");
        const hookCommand = !mcp && SHELL_TOOLS.has(normalized.tool) && typeof command === "string" ? command : undefined;
        await context.engine.recordToolResult(id, normalized.tool, result, {
          ...restInspection,
          ...(cliSampled ? { sampled: true } : {}),
          ...(allSampledDestinations.length > 0 ? { sampledDestinations: allSampledDestinations } : {}),
          ...(toolUseId ? { toolUseId } : {}),
          ...(hookCommand !== undefined ? { command: hookCommand } : {}),
          ...((input.client === "codex" || input.client === "gemini") && analysis?.copies.length ? { fileCopies: analysis.copies } : {}),
          agentId: input.client === "claude-code" ? payloadField(record, "agent_id") : undefined
        }, normalized.input);
        return { exitCode: 0, output: undefined, reason: "Tool output registered." };
      }
      const request: JsonRpcMessage = {
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: { name: normalized.tool, arguments: enrichToolArguments(normalized, analysis) }
      };
      const readsSensitivePath = analysis?.readTargets.some((path) => sensitiveFile(path, cwd));
      const inspectionOnly = Boolean(analysis && typeof command === "string" && isSafeInspectionShellCommand(command, cwd));
      const toolUseId = payloadField(record, "tool_use_id");
      const hookCommand = !mcp && SHELL_TOOLS.has(normalized.tool) && typeof command === "string" ? command : undefined;
      const output = await context.engine.handleClientMessage(request, readsSensitivePath, {
        inspectionOnly,
        hookExec: {
          canAsk: input.client !== "codex" && input.client !== "gemini",
          ...(toolUseId ? { toolUseId } : {}),
          ...(hookCommand !== undefined && analysis ? {
            command: hookCommand, analysis,
            referencesSensitivePath: () => analysis.sensitiveRead || analysis.pathOperands.some((path) => sensitiveFile(path, cwd))
              || analysis.readTargets.some((path) => externalFile(path, cwd))
          } : {})
        }
      });
      if (output.toServer.length > 0) {
        return { exitCode: 0, output: undefined, reason: "Allowed by policy." };
      }
      const requestEvent = context.events.find((event) => event.direction === "request");
      const action = requestEvent?.action ?? "block";
      const reason = requestEvent?.reason ?? "Palizade blocked this native tool call.";
      if (action === "require_approval") {
        // The client shows this on its own approval prompt, where "approval denied" would read as already refused.
        return buildAskOutput(input.client, input.event, reason.replace(`; approval denied (${HOOKS_DEFER})`, ""));
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
  if (client === "gemini") {
    return { exitCode: 0, output: { decision: "deny", reason }, reason };
  }
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
  // Codex parses "ask" but runs the tool anyway, so an approval there must be a deny.
  // Gemini CLI has no ask at all.
  if (client === "codex" || client === "gemini") {
    return buildDenyOutput(client, event, `Palizade needs your approval for this call, and ${client === "codex" ? "Codex" : "Gemini CLI"} hooks cannot ask; run it yourself if you approve. ${reason}`);
  }
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
