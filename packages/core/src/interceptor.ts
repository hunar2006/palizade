import type { ApprovalDecision, ApprovalProvider } from "@palizade/approvals";
import { randomUUID } from "node:crypto";
import { createApprovalRequest } from "@palizade/approvals";
import type { AuditLogger } from "@palizade/audit";
import type { DetectionResult, Detector, DetectorContext } from "@palizade/detectors";
import { fuseDetections, hasPiiLabel, hasSecretLabel, maskKnownSensitiveText, maskSensitiveText, stripHiddenUnicode } from "@palizade/detectors";
import { evaluatePolicy, type PolicyDecision, type PolicyDocument, type ToolClass } from "@palizade/policy";
import type { SessionState, TaintClass, TaintMatch, TaintRecord, TaintStore } from "@palizade/taint";
import { expireExposure, maskStatedObservables, expandCandidates, extractAtomicTokens, extractDestinationObservables, canonicalHost, hostSkeleton, isMatchableToken, normalizeText, OutboundWindow, sha256 } from "@palizade/taint";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { extractArgumentFields, argumentRolesSummary, type ArgumentField } from "./arguments.js";
import { classifyToolDetailed, type ToolClassification } from "./classifier.js";
import type { PalizadeConfig, ServerConfig } from "./config.js";
import { DEFAULT_NON_INTERACTIVE_WRITE_GATE_TTL_MS, palizadeConfigSchema, serverConfigSchema } from "./config.js";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { contentText, extractContent, type ContentOrigin, type ExtractedContent } from "./content.js";
import type { LockfileStore, ToolLockCheck } from "./lockfile.js";
import { destinationEntries, destinationsAllowed, LearnedEgress } from "./egress.js";
import { trackSinkAttempt } from "./session-gates.js";
import { DEFAULT_METADATA_GUARD_CONFIG, InMemoryToolRegistry, reviewMetadata, stripHiddenUnicodeDeep, type MetadataItem, type MetadataReview, type ToolRegistry } from "./metadata-guard.js";
import { checkProtectedPaths, escapeNonPrinting, isWorkspacePath, protectedWriteDiff, resolveArgumentPath } from "./protected-paths.js";
import { checkGitPush } from "./git-egress.js";
import type { ShellAnalysis } from "./hooks.js";
import { isAllowedCopiedLocalCommand } from "./copied-commands.js";
import { canaryStorePath, containsCanary, readCanaries, type Canary } from "./canary.js";
import { stableStringify } from "./canonical.js";
import {
  isRequest,
  isSuccess,
  makeErrorResponse,
  makeToolErrorResultResponse,
  type JsonRpcId,
  type JsonRpcFailure,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpTool,
  type ToolsCallParams,
  type ToolsListResult
} from "./mcp.js";
import { applyTextTransforms, extractTextBlocks, flattenArguments, isSpotlightableText, redactSpans, spotlightText, textPathKey, type TextBlock } from "./text.js";
import { detectEra, isServerNotification, isToolsListChanged, PROTOCOL_VERSION_META_KEY, SENSITIVE_FIELD_NAME_RE, type McpEra } from "./era.js";

export interface InterceptionEngineOptions {
  config: PalizadeConfig;
  serverName: string;
  server: ServerConfig;
  sessionId: string;
  policy: PolicyDocument;
  detector: Detector;
  taintStore: TaintStore;
  audit: AuditLogger;
  approvals: ApprovalProvider;
  lockfile: LockfileStore;
  toolRegistry?: ToolRegistry | undefined;
  checkSeal?: () => string[];
  sealedLearnedEgress?: LearnedEgress | undefined;
}

export interface EngineOutput {
  toClient: JsonRpcMessage[];
  toServer: JsonRpcMessage[];
}

interface DestinationSummary {
  allowed: boolean;
  allowlistConfigured: boolean;
  hosts: string[];
  emailRecipients: string[];
  destinationCount: number;
}

const DESTINATION_ROLES = new Set(["url", "hostname", "email_recipient", "repository_destination", "channel_id", "account_id"]);
const NATIVE_WORKSPACE_WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch", "write_file", "replace"]);
const SHORT_SENSITIVE_SHELL_COMMAND = /^(?:env|set)$/iu;
const EXECUTABLE_OR_BUILD_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
  ".py", ".pyw", ".ipynb", ".sh", ".bash", ".zsh", ".fish",
  ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".wsf",
  ".rb", ".pl", ".php", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
  ".cs", ".fs", ".java", ".kt", ".kts", ".scala", ".swift", ".lua", ".r", ".jl",
  ".ex", ".exs", ".erl", ".clj", ".hs", ".zig", ".nim", ".awk", ".sed",
  ".makefile", ".mk", ".cmake", ".gradle", ".csproj", ".fsproj", ".vbproj",
  ".props", ".targets", ".dockerfile", ".nix", ".tf", ".hcl", ".wasm"
]);
const EXECUTABLE_OR_BUILD_BASENAMES = new Set([
  "makefile", "gnumakefile", "justfile", "rakefile", "gemfile", "podfile",
  "vagrantfile", "dockerfile", "containerfile", "jenkinsfile", "cmakelists.txt",
  "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml", "go.mod",
  "pom.xml", "build.xml", "meson.build", "build", "build.bazel", "workspace",
  "flake.nix", "procfile", "taskfile.yml", "taskfile.yaml"
]);

interface PendingClientRequest {
  sensitive?: boolean;
  inspectionOnly?: boolean;
  unmatchedNativeWrite?: boolean;
  taintedCodeWriteGeneration?: number;
  method: string;
  tool?: string | undefined;
  startedAt: number;
  relock?: boolean;
}

interface HookToolResultOptions {
  destinationOnly?: boolean;
  workspaceSource?: boolean;
  sensitivePath?: boolean;
  singleTextBlock?: boolean;
  sampled?: boolean;
  truncated?: boolean;
  sampledDestinations?: string[];
  inspectionOnly?: boolean;
  toolUseId?: string | undefined;
  command?: string | undefined;
  fileCopies?: ShellAnalysis["copies"];
  agentId?: string | undefined;
  agentResult?: { id: string | undefined; report: string };
}

interface HookExecution {
  canAsk: boolean;
  toolUseId?: string;
  command?: string;
  analysis?: ShellAnalysis;
  referencesSensitivePath?: () => boolean;
}

export class InterceptionEngine {
  private readonly pendingClient = new Map<JsonRpcId, PendingClientRequest>();
  private readonly knownTools = new Map<string, McpTool>();
  private learnedEgress: LearnedEgress;
  private lastReloadFailure: string | undefined;
  private lastCanaryStoreFailure: string | undefined;
  private readonly outboundWindow = new OutboundWindow();
  private clientEra: McpEra | undefined;
  private serverEra: McpEra | undefined;
  private readonly metadataBlockedTools = new Map<string, PolicyDecision>();
  private readonly toolRegistry: ToolRegistry;
  private sealedSessionDestinations: Set<string> | undefined;

  constructor(private options: InterceptionEngineOptions) {
    const config = palizadeConfigSchema.parse(options.config);
    if (!options.config.egress.learnedFile) config.egress.learnedFile = resolve(dirname(config.lockfile), "palizade.allow.yaml");
    this.options = { ...options, config, server: serverConfigSchema.parse(options.server) };
    this.learnedEgress = options.sealedLearnedEgress ?? this.createLearnedEgress(config);
    if (options.sealedLearnedEgress) this.sealedSessionDestinations = new Set();
    this.toolRegistry = options.toolRegistry ?? new InMemoryToolRegistry();
  }

  get currentPolicy(): PolicyDocument {
    return this.options.policy;
  }

  get currentConfig(): PalizadeConfig {
    return this.options.config;
  }

  /** Swaps in an already validated policy and/or config. Throws, leaving the engine unchanged, if the new config no longer defines this server. */
  reload(update: { policy?: PolicyDocument | undefined; config?: PalizadeConfig | undefined }): void {
    if (this.options.sealedLearnedEgress) throw new Error("A sealed engine must be restarted to load changes.");
    const config = update.config ? palizadeConfigSchema.parse(update.config) : this.options.config;
    const server = update.config ? config.servers[this.options.serverName] : this.options.server;
    if (!server) throw new Error(`Server '${this.options.serverName}' is no longer defined in palizade.yaml.`);
    const learnedEgress = config.egress.learnedFile !== this.learnedEgress.path ? this.createLearnedEgress(config) : this.learnedEgress;
    // shortcut: a message already being processed may evaluate later rules against the new document; snapshot options per message if mid-message consistency is ever required.
    this.options = { ...this.options, policy: update.policy ?? this.options.policy, config, server: serverConfigSchema.parse(server) };
    this.learnedEgress = learnedEgress;
  }

  /** Re-validates the learned allowlist file now; with hot reload on, a bad file keeps the previous version. */
  validateLearnedEgress(): void {
    this.learnedEgress.validate();
  }

  private createLearnedEgress(config: PalizadeConfig): LearnedEgress {
    if (config.reload?.enabled === false) return new LearnedEgress(config.egress.learnedFile);
    return new LearnedEgress(config.egress.learnedFile, (error) => this.reportReloadFailure("allowlist", config.egress.learnedFile, error));
  }

  private reportReloadFailure(kind: string, file: string, error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    const key = `${kind}:${file}:${message}`;
    if (this.lastReloadFailure === key) return;
    this.lastReloadFailure = key;
    console.warn(`[palizade] ${file} is invalid; keeping the previous ${kind}.\n${message}`);
    void this.options.audit.write({
      session: this.options.sessionId,
      server: this.options.serverName,
      direction: "internal",
      method: "config/reload",
      action: "log_only",
      reason: `Rejected invalid ${kind} ${file}; kept the previous version.`,
      metadata: { reload: { kind, file, ok: false, error: message.slice(0, 2000) } }
    }).catch(() => undefined);
  }

  private async reportCanaryStoreFailure(error: unknown): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    if (this.lastCanaryStoreFailure === message) return;
    this.lastCanaryStoreFailure = message;
    console.warn(`[palizade] ${message}`);
    await this.options.audit.write({
      session: this.options.sessionId,
      server: this.options.serverName,
      direction: "internal",
      method: "canary/read",
      action: "log_only",
      reason: message,
      metadata: { canary: { file: canaryStorePath(this.options.config), ok: false, error: message.slice(0, 2000) } }
    }).catch(() => undefined);
  }

  releasePendingRequest(id: JsonRpcId): boolean {
    return this.pendingClient.delete(id);
  }

  async handleClientMessage(
    message: JsonRpcMessage,
    readsSensitivePath = false,
    options?: { inspectionOnly?: boolean; hookExec?: HookExecution }
  ): Promise<EngineOutput> {
    if (!isRequest(message)) {
      return { toClient: [], toServer: [message] };
    }

    if (this.options.checkSeal) {
      let reason: string | undefined;
      try {
        const drift = this.options.checkSeal();
        if (drift.length > 0) reason = `Palizade seal verification failed (${drift.map((file) => basename(file)).join(", ")}). Approve the files with palizade seal and restart the wrapper.`;
      } catch {
        reason = "Palizade could not verify the seal. Check the operator-managed seal and restart the wrapper.";
      }
      if (reason) {
        await this.auditDecision(message, "request", { action: "block", reason, failClosed: true }, Date.now(), { metadata: { seal: "drift" } });
        const response = message.id === undefined ? [] : [message.method === "tools/call"
          ? makeToolErrorResultResponse(message.id, reason, this.isModernEra(message))
          : makeErrorResponse(message.id, -32028, reason)];
        return { toClient: response, toServer: [] };
      }
    }

    const detectedEra = detectEra(message);
    if (detectedEra !== undefined) {
      this.clientEra = detectedEra;
    }

    if (message.method === "initialize") {
      this.recordPending(message);
      await this.auditDecision(message, "request", { action: "allow", reason: "initialize forwarded" }, Date.now());
      return { toClient: [], toServer: [message] };
    }

    if (message.method === "tools/call") {
      try { return await this.handleToolCallRequest(message, readsSensitivePath, options?.inspectionOnly, options?.hookExec); }
      catch {
        const decision: PolicyDecision = { action: this.options.policy.defaults.on_error, reason: "Security decision failed", failClosed: true };
        const approval = await this.maybeApprove(decision, { method: message.method, toolClass: "unknown", taintMatches: [], summary: "Security decision failed." });
        await this.auditDecision(message, "request", approval.decision, Date.now());
        if (approval.approved && decision.action !== "block") { this.recordPending(message); return { toClient: [], toServer: [message] }; }
        return { toClient: message.id === undefined ? [] : [makeToolErrorResultResponse(message.id, "Palizade blocked this tool call: security decision failed.", this.isModernEra(message))], toServer: [] };
      }
    }

    this.recordPending(message);
    return { toClient: [], toServer: [message] };
  }

  async handleServerMessage(message: JsonRpcMessage): Promise<EngineOutput> {
    try { return await this.processServerMessage(message); }
    catch {
      const decision: PolicyDecision = { action: this.options.policy.defaults.on_error, reason: "Security response decision failed", failClosed: true };
      const approval = await this.maybeApprove(decision, { method: "security/error", toolClass: "unknown", taintMatches: [], summary: "Security response decision failed." });
      await this.auditDecision(message, "response", approval.decision, Date.now());
      if (approval.approved && decision.action !== "block") return { toClient: [message], toServer: [] };
      if (isRequest(message)) return { toClient: [], toServer: message.id === undefined ? [] : [makeErrorResponse(message.id, -32028, "Security decision failed")] };
      return { toClient: [makeErrorResponse(message.id, -32028, "Security decision failed")], toServer: [] };
    }
  }

  private async processServerMessage(message: JsonRpcMessage): Promise<EngineOutput> {
    if (!isRequest(message) && !this.pendingClient.has(message.id)) {
      await this.auditDecision(message, "response", { action: "log_only", reason: "Dropped unsolicited upstream response." }, Date.now()).catch(() => undefined);
      return { toClient: [], toServer: [] };
    }
    const detectedEra = detectEra(message);
    if (detectedEra !== undefined) {
      this.serverEra = detectedEra;
    }

    if (isServerNotification(message)) {
      return this.handleServerNotification(message);
    }

    if (isRequest(message)) {
      return this.handleServerInitiatedRequest(message);
    }

    const pending = this.pendingClient.get(message.id)!;
    this.pendingClient.delete(message.id);
    if (pending.method === "tools/call") {
      return this.handleToolCallResponse(message, pending);
    }
    if (pending.method === "resources/read") {
      return this.handleGenericContentResponse(message, pending, "resource_content");
    }
    if (pending.method === "prompts/get") {
      return this.handleGenericContentResponse(message, pending, "prompt_content");
    }
    if (!isSuccess(message) && pending.relock) {
      await this.auditDecision(message, "response", { action: "log_only", reason: "Upstream tool list refresh failed." }, pending.startedAt, { method: pending.method });
      return { toClient: [], toServer: [] };
    }
    if (!isSuccess(message)) return { toClient: [message], toServer: [] };

    if (pending.method === "tools/list") {
      return this.handleToolsListResponse(message, pending);
    }
    if (pending.method === "server/discover") {
      return this.handleServerDiscoverResponse(message);
    }
    if (pending.method === "resources/list") {
      return this.handleDescriptorListResponse(message, "resources", "resource_metadata", "resources", (item) => descriptorName(item, "resource"));
    }
    if (pending.method === "resources/templates/list") {
      return this.handleDescriptorListResponse(message, "resourceTemplates", "resource_metadata", "resourceTemplates", (item) => descriptorName(item, "resourceTemplate"));
    }
    if (pending.method === "prompts/list") {
      return this.handleDescriptorListResponse(message, "prompts", "prompt_metadata", "prompts", (item) => descriptorName(item, "prompt"));
    }
    if (pending.method === "subscriptions/listen") {
      return this.handleGenericContentResponse(message, pending, "notification");
    }
    if (pending.method === "initialize") {
      return this.handleInitializeResponse(message);
    }
    if (pending.method === "server/discover") {
      return this.handleDiscoverMetadataResponse(message);
    }

    return { toClient: [message], toServer: [] };
  }

  private async handleToolCallRequest(
    message: JsonRpcRequest,
    readsSensitivePath: boolean,
    inspectionOnly = false,
    hookExec?: HookExecution
  ): Promise<EngineOutput> {
    const startedAt = Date.now();
    const params = (message.params ?? {}) as ToolsCallParams;
    const tool = params.name ?? "unknown";
    const metadataBlocked = this.metadataBlockedTools.get(tool);
    if (metadataBlocked) {
      return this.blockToolCallForMetadata(message, tool, metadataBlocked, startedAt);
    }
    const knownTool = this.knownTools.get(tool);
    const classification = classifyToolDetailed(tool, this.options.server, knownTool);
    const toolClass = classification.toolClass;
    await this.expireQuarantine();
    let session = this.options.taintStore.getSession(this.options.sessionId);
    if (expireExposure(session, this.options.config.taint.exposure.ttlMs) !== session) {
      session = this.options.taintStore.updateSession(this.options.sessionId, (state) => expireExposure(state, this.options.config.taint.exposure.ttlMs));
    }
    const ruleOfTwo = session.seenUntrusted && (session.seenSensitive || readsSensitivePath);
    const argumentText = flattenArguments(params.arguments);
    const matchCache = new Map<string, TaintMatch[]>();
    // Destinations the user typed are theirs even if untrusted content also mentions them.
    const userIntent = this.options.config.taint.userIntent.enabled && this.options.taintStore.hasUserStatements(this.options.sessionId);
    const userStated = new Set<string>();
    const unstated = (text: string): string => {
      if (!userIntent) return text;
      const result = maskStatedObservables(text, (canonical) => this.options.taintStore.isUserStated(this.options.sessionId, canonical));
      result.masked.forEach((canonical) => userStated.add(canonical));
      return result.text;
    };
    const matchText = (raw: string, destinationRole = false): TaintMatch[] => {
      const text = unstated(raw);
      const cacheKey = `${destinationRole ? "dest" : "gen"}:${text}`;
      if (!matchCache.has(cacheKey)) matchCache.set(cacheKey, expandCandidates(text, this.options.config.taint.decode).flatMap((candidate) =>
        this.options.taintStore.match(this.options.sessionId, candidate.text, {
          fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax,
          ...(destinationRole ? { destinationRole: true } : {})
        })
          .map((match): TaintMatch => ({ ...match, reason: candidate.kind === "original" || match.reason === "temporal" ? match.reason : `decoded:${candidate.kind}` }))));
      return matchCache.get(cacheKey)!;
    };
    const argumentFields = extractArgumentFields(params.arguments, tool, { ...classification.argumentRoles, ...this.options.server.argumentRoles?.[tool] });
    const cwd = this.options.server.cwd ?? process.cwd();
    const protectedPaths = checkProtectedPaths(argumentFields, cwd, this.options.config);
    const criticalPath = protectedPaths.critical || shellReferencesManagedSeal(argumentFields, cwd);
    const isNativeFileWriter = this.options.serverName === "native-tools"
      && this.options.server.command === "native-tools"
      && NATIVE_WORKSPACE_WRITE_TOOLS.has(tool);
    const localWorkspaceWrite = isNativeFileWriter
      && classification.capabilities.length > 0
      && classification.capabilities.every((capability) => capability === "file_write" || capability === "writes_local")
      && !criticalPath
      && isSafeWorkspaceCwd(cwd)
      && protectedPaths.resolved.length > 0
      && protectedPaths.resolved.every((path) => !path.uncertain && isWorkspacePath(path, cwd));
    const writesFile = classification.capabilities.some((capability) => ["file_write", "writes_local", "deletes_data"].includes(capability));
    const argumentBlocks = extractTextBlocks(params.arguments);
    const argumentDetections = await Promise.all(argumentBlocks.map(async (block) => ({
      block,
      detection: await this.options.detector.detect(block.text, {
        server: this.options.serverName,
        tool,
        trust: this.options.server.trust,
        surface: "argument"
      })
    })));
    const argumentDetection = fuseDetections(argumentDetections.map((entry) => entry.detection));
    const argumentDetectionsByPath = new Map(argumentDetections.map((entry) => [pathKey(entry.block), entry.detection]));
    const matches = matchText(argumentText, false);
    const fieldMatches = argumentFields.flatMap((field) => matchText(field.text, DESTINATION_ROLES.has(field.role)).map((match) => ({ field, match })));
    const commandField = hookExec?.analysis && argumentFields.find((field) => field.path === "$.command" && field.role === "shell_command");
    const normalizedCommand = commandField && normalizeText(commandField.text);
    if (commandField && normalizedCommand && normalizedCommand.length < 16) {
      const minNormalizedLength = hookExec?.analysis?.sensitiveRead && SHORT_SENSITIVE_SHELL_COMMAND.test(normalizedCommand) ? 3 : 8;
      for (const match of this.options.taintStore.match(this.options.sessionId, commandField.text, { minNormalizedLength })) {
        if (match.reason === "substring") fieldMatches.push({ field: commandField, match });
      }
    }
    const commandMatch = commandField && fieldMatches.find(({ field, match }) =>
      field === commandField && match.reason !== "temporal" && !match.reason.startsWith("decoded:") && match.classes?.includes("untrusted"))?.match;
    const sensitiveMatches = matches.filter((match) => match.classes?.includes("sensitive"));
    const sensitiveFieldMatches = fieldMatches.filter(({ match }) => match.classes?.includes("sensitive"));
    const taintedArgumentRoles = [...new Set(fieldMatches.filter(({ match }) => match.reason !== "temporal").map(({ field }) => field.role))];
    const taintedDestination = fieldMatches.some(({ field, match }) => DESTINATION_ROLES.has(field.role) && match.reason !== "temporal" && match.classes?.includes("untrusted"));
    const temporal = matches.some((match) => match.reason === "temporal") || this.options.taintStore.hasTemporal(this.options.sessionId);
    const secretDetected = hasSecretLabel(argumentDetection.labels);
    const piiDetected = hasPiiLabel(argumentDetection.labels);
    let sensitiveTaint = sensitiveMatches.some((match) => match.reason !== "temporal") || sensitiveFieldMatches.some(({ match }) => match.reason !== "temporal");
    const allowlist = this.learnedEgress.allowlist(this.options.config.egress.allowlist);
    const gitPush = checkGitPush(tool, argumentFields, this.options.server.cwd ?? process.cwd(), allowlist);
    const entries = destinationEntries(argumentFields);
    for (const entry of gitPush.destinations) if (!entries.includes(entry)) entries.push(entry);
    if (classification.capabilities.includes("persists_memory") && entries.length === 0) entries.push(`memory:${this.options.serverName}`);
    const destinationKeys = entries.map((entry) => this.options.taintStore.destinationKey(entry));
    // Only outbound calls feed the loop and rate gates: a coding agent running `npm test` ten
    // times is normal, sending the same email ten times is not.
    const outbound = entries.length > 0 || classification.capabilities.some((capability) => ["sends_message", "writes_remote", "deletes_data", "persists_memory"].includes(capability));
    const gates = toolClass === "sink" && outbound ? trackSinkAttempt(this.options.taintStore, this.options.sessionId, this.options.taintStore.destinationKey(`${tool}\0${argumentText}`), destinationKeys, this.options.config.limits) : { rateLimited: false, loopDetected: false };
    const sessionTrusted = destinationKeys.length > 0 && destinationKeys.every((key) => this.sealedSessionDestinations?.has(key) ?? session.trustedDestinations.includes(key));
    const newDestination = entries.length > 0 && !destinationsAllowed(entries, allowlist);
    const outboundPayload = argumentFields.filter((field) => !field.path.includes("<")).flatMap((field) => {
      if (field.role === "url") {
        try { return [...new URL(field.text).searchParams.values()]; } catch { return []; }
      }
      return ["hostname", "email_recipient", "repository_destination", "channel_id", "account_id", "file_path"].includes(field.role) ? [] : [field.text];
    }).join("");
    const splitMatches = toolClass !== "sink" ? [] : entries.flatMap((entry) => {
      const combined = this.outboundWindow.append(this.options.sessionId, entry, outboundPayload || argumentText, this.options.config.taint.window);
      return combined === undefined ? [] : expandCandidates(combined, this.options.config.taint.decode).flatMap((candidate) => this.options.taintStore.match(this.options.sessionId, candidate.text, { fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax, sensitiveFragments: true }).filter((match) => match.reason !== "temporal"));
    });
    const splitMatch = splitMatches.some((match) => !matches.some((current) => current.reason !== "temporal" && current.taintId === match.taintId));
    sensitiveTaint ||= splitMatches.some((match) => match.classes?.includes("sensitive"));
    const destination = summarizeDestinations(argumentFields, allowlist, (value) => matchText(value, true).some((match) => match.reason !== "temporal"));
    const lookalikeDestination = destination.hosts.some((host) => {
      const skeleton = hostSkeleton(host);
      return skeleton !== canonicalHost(host) && (allowlist.hosts.some((allowed) => hostSkeleton(allowed) === skeleton) || matchText(skeleton, true).some((match) => match.reason !== "temporal" && match.classes?.includes("untrusted")));
    });
    const safeDestination = { ...destination, hosts: destination.hosts.map((host) => matchText(host, true).some((match) => match.reason !== "temporal") ? "[REDACTED:tainted-host]" : maskKnownSensitiveText(host)) };
    const allTaintMatches = [
      ...matches,
      ...fieldMatches.map(({ match }) => match),
      ...sensitiveMatches,
      ...sensitiveFieldMatches.map(({ match }) => match),
      ...splitMatches
    ];

    const inputResponses = (params as { inputResponses?: unknown }).inputResponses;
    let inputResponseTaint = false;
    let inputResponseSensitive = false;
    const inputResponseMatches: TaintMatch[] = [];
    if (inputResponses !== undefined && inputResponses !== null) {
      const responseText = flattenArguments(inputResponses);
      const responseFields = extractArgumentFields(inputResponses, tool, this.options.server.argumentRoles?.[tool]);
      const rawMatches = [...matchText(responseText, false), ...responseFields.flatMap((field) => matchText(field.text, DESTINATION_ROLES.has(field.role)))];
      const seen = new Set<string>();
      for (const match of rawMatches) {
        if (seen.has(match.taintId)) {
          continue;
        }
        seen.add(match.taintId);
        inputResponseMatches.push(match);
      }
      inputResponseTaint = inputResponseMatches.some((match) => match.reason !== "temporal");
      inputResponseSensitive = inputResponseMatches.some((match) => match.reason !== "temporal" && match.classes?.includes("sensitive"));
      allTaintMatches.push(...inputResponseMatches);
    }

    // Following a link exactly as an untrusted page wrote it leaks nothing the page's author did
    // not already have; building a url from page text, or adding data to it, still counts as copied.
    const verbatimLinks = toolClass === "sink" && taintedDestination
      && classification.capabilities.every((capability) => capability === "network_egress" || capability === "reads_untrusted_content")
      ? argumentFields.filter((field) => field.role === "url" && /^https?:\/\/\S+$/u.test(field.text.trim()) && this.options.taintStore.verbatimToken(this.options.sessionId, field.text.trim()) !== undefined).map((field) => field.text.trim())
      : [];
    const copiedLinkOnly = verbatimLinks.length > 0 && !sensitiveTaint && !secretDetected && !piiDetected && !splitMatch && !inputResponseTaint
      // Derived fields (a url's host, path "url<host>") come from the link itself.
      && fieldMatches.every(({ field, match }) => match.reason === "temporal" || verbatimLinks.includes(field.text.trim()) || (field.path.includes("<") && verbatimLinks.some((link) => link.toLowerCase().includes(field.text.trim().toLowerCase()))))
      && !matchText(verbatimLinks.reduce((text, link) => text.split(link).join(" "), argumentText), false).some((match) => match.reason !== "temporal");

    // Rewriting the file a canary lives in (an edit to .env) is not a leak; any other call carrying one is.
    const localWriteOnly = classification.capabilities.length > 0 && classification.capabilities.every((capability) => ["file_write", "writes_local", "deletes_data", "reads_sensitive_data"].includes(capability));
    let canaries: Canary[] = [];
    if (!localWriteOnly) {
      try {
        canaries = readCanaries(this.options.config);
      } catch (error) {
        await this.reportCanaryStoreFailure(error);
      }
    }
    const canaryLeaving = !localWriteOnly && containsCanary(argumentText, canaries, this.options.config.taint.decode);
    const taintedLocalCommand = Boolean(commandMatch && commandField && hookExec?.analysis
      && isAllowedCopiedLocalCommand(commandField.text, cwd)
      && this.options.serverName === "native-tools" && this.options.server.command === "native-tools"
      && classification.capabilities.includes("executes_code") && stripHiddenUnicode(commandField.text) === commandField.text
      && entries.length === 0 && !taintedDestination && !gitPush.unapproved && !splitMatch
      && !session.seenSensitive && !session.quarantine && !readsSensitivePath && !hookExec.referencesSensitivePath?.()
      && !criticalPath && !checkProtectedPaths(hookExec.analysis.pathOperands.map((text) => ({ path: "$.command", role: "file_path", text })), cwd, this.options.config, true).critical
      && !sensitiveTaint && !inputResponseSensitive && !secretDetected && !piiDetected && !canaryLeaving
      && !extractDestinationObservables(commandField.text, true).some((value) => this.options.taintStore.match(this.options.sessionId, value, {
        destinationRole: true, classes: ["untrusted"]
      }).some(({ reason }) => reason !== "temporal")));
    const writeGate = session.taintedCodeWrite;
    const gateNow = Date.now();
    const nonInteractive = hookExec?.canAsk === false;
    const writeGateTtl = nonInteractive
      ? this.options.config.hooks.nonInteractiveWriteGateTtlMs ?? DEFAULT_NON_INTERACTIVE_WRITE_GATE_TTL_MS
      : this.options.config.taint.exposure.ttlMs;
    let pendingWriteFiles = writeGate && writeGate.expiresAt > gateNow ? writeGate.files : [];
    if (nonInteractive && writeGate && pendingWriteFiles.length) {
      const operands = new Set(hookExec.analysis?.executionOperands.map(writtenBasename));
      const activeEntries = writeEntries(writeGate).filter(({ expiresAt, writtenAt }) =>
        gateNow < Math.min(expiresAt, (writtenAt ?? expiresAt - this.options.config.taint.exposure.ttlMs) + writeGateTtl));
      const aliases = operands.size > 0 ? copiedWriteEntries(activeEntries, hookExec.analysis?.copies ?? [], cwd) : [];
      pendingWriteFiles = dedupePreservingOrder([...activeEntries, ...aliases].filter(({ file }) =>
        isExecutableOrBuildFile(file) || operands.has(writtenBasename(file))).map(({ file }) => file)).slice(-10);
    }
    const taintedCodeWritePending = !inspectionOnly && pendingWriteFiles.length > 0;

    const policyDecision = evaluatePolicy(this.options.policy, {
      direction: "request",
      method: message.method,
      server: this.options.serverName,
      tool,
      tool_class: toolClass,
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: matches.some((match) => match.reason !== "temporal") || fieldMatches.some(({ match }) => match.reason !== "temporal") || inputResponseTaint,
      sensitive_taint: sensitiveTaint || inputResponseSensitive,
      temporal_taint: temporal,
      secret_detected: secretDetected,
      pii_detected: piiDetected,
      destination_allowed: destination.allowed,
      tainted_destination: taintedDestination,
      user_stated_destination: userStated.size > 0,
      copied_link_only: copiedLinkOnly,
      lookalike_destination: lookalikeDestination,
      new_destination: newDestination,
      split_match: splitMatch,
      rule_of_two: ruleOfTwo,
      session_untrusted: session.seenUntrusted,
      destination_session_trusted: sessionTrusted,
      session_quarantined: Boolean(session.quarantine),
      tainted_code_write_pending: taintedCodeWritePending,
      tainted_local_command: taintedLocalCommand,
      rate_limited: gates.rateLimited,
      loop_detected: gates.loopDetected,
      critical_path: criticalPath,
      local_workspace_write: localWorkspaceWrite,
      argument_paths: protectedPaths.paths,
      output_path_allowed: writesFile && protectedPaths.outputAllowed,
      git_push_unapproved: gitPush.unapproved,
      destination_allowlist_configured: destination.allowlistConfigured,
      detector_score: argumentDetection.score,
      labels: canaryLeaving ? [...argumentDetection.labels, "canary"] : argumentDetection.labels,
      argument_text: argumentText,
      argument_roles: argumentRolesSummary(argumentFields),
      tainted_argument_roles: taintedArgumentRoles,
      tool_metadata_taint: [...matches, ...fieldMatches.map(({ match }) => match)].some((match) => match.reason !== "temporal" && this.options.taintStore.get(match.taintId)?.labels.includes("tool_metadata"))
    });

    const egressGate = toolClass === "sink" && newDestination && this.options.config.egress.mode !== "open" && !(this.options.config.egress.mode === "approve_new" && sessionTrusted);
    let decision: PolicyDecision = policyDecision.action === "block" || !egressGate ? policyDecision : {
      action: this.options.config.egress.mode === "allowlist_only" ? "block" : "require_approval",
      matchedRuleId: "egress-new-destination",
      reason: "Destination is not in the egress allowlist."
    };
    if (decision.matchedRuleId === "approve-exec-after-tainted-code-write" && pendingWriteFiles.length) {
      const noun = pendingWriteFiles.some((file) => isExecutableOrBuildFile(file))
        ? "code or build file"
        : "file";
      decision = {
        ...decision,
        reason: `A workspace ${noun} (${pendingWriteFiles.map((file) => basename(file)).join(", ")}) was written using text from an untrusted source. Review the edit before running this command.`
      };
    }
    if (decision.matchedRuleId === "approve-tainted-local-command" && commandMatch) {
      const record = this.options.taintStore.get(commandMatch.taintId);
      const scriptFiles = hookExec?.analysis?.scriptFiles;
      let reason = decision.reason;
      if (record) {
        const { sourceServer, sourceTool } = record;
        const source = sourceServer === "native-tools" ? sourceTool : sourceServer + "/" + sourceTool;
        reason = sourceServer === "native-tools" && NATIVE_WORKSPACE_WRITE_TOOLS.has(sourceTool)
          ? "This command's text matches a file written in this session that contained outside text."
          : trimTrailingPeriod(reason) + " (" + escapeNonPrinting(maskKnownSensitiveText(source)) + ").";
      }
      if (scriptFiles?.length) {
        reason += " It can run code from " + escapeNonPrinting(maskKnownSensitiveText(scriptFiles.join(", "))) + ", whose contents Palizade did not check.";
      }
      decision = { ...decision, reason };
    }

    const approval = await this.maybeApprove(decision, {
      method: message.method,
      tool,
      toolClass,
      classification,
      taintMatches: allTaintMatches,
      rememberDestinations: egressGate && decision.action === "require_approval" ? entries : [],
      trustSessionDestinations: (ruleOfTwo || (this.options.sealedLearnedEgress && egressGate)) && decision.action === "require_approval" ? destinationKeys : [],
      details: protectedPaths.critical && writesFile && decision.action === "require_approval" ? {
        diff: protectedPaths.resolved.map((path) => path.uncertain
          ? "Target path could not be safely canonicalized; review the raw path before approving."
          : protectedWriteDiff(path.canonical, params.arguments, this.options.config.protectedTargets.maxDiffBytes, allTaintMatches.some((match) => match.reason !== "temporal"), (text) => this.options.taintStore.match(this.options.sessionId, text).some((match) => match.reason !== "temporal"))).join("\n\n")
      } : {},
      summary: formatToolCallApprovalSummary({
        tool,
        toolClass,
        capabilities: classification.capabilities,
        taintMatches: allTaintMatches,
        taintedArgumentRoles,
        destination: safeDestination,
        taintStore: this.options.taintStore
      })
    });

    await this.auditDecision(message, "request", approval.decision, startedAt, {
      tool,
      toolClass,
      classification,
      detector: argumentDetection,
      taintMatches: allTaintMatches,
      approved: approval.approved,
      argumentRoles: argumentRolesSummary(argumentFields),
      taintedArgumentRoles,
      destination: safeDestination,
      sensitiveTaint,
      secretDetected,
      piiDetected,
      taintClasses: classesFromMatches(allTaintMatches),
      redacted: policyDecision.action === "redact_secrets",
      ...(userStated.size > 0 ? { metadata: { userStatedDestinations: userStated.size } } : {})
    });

    this.options.taintStore.consumeTurn(this.options.sessionId);
    if (!approval.approved || decision.action === "block") {
      if (decision.action === "block" && (taintedDestination || splitMatch || lookalikeDestination)) await this.startQuarantine("Blocked risky outbound destination or split match.");
    }
    const quarantine = this.options.taintStore.getSession(this.options.sessionId).quarantine;
    if (quarantine) {
      this.options.taintStore.updateSession(this.options.sessionId, (state) => ({ ...state, quarantine: state.quarantine ? { ...state.quarantine, remainingTurns: state.quarantine.remainingTurns - 1 } : undefined }));
      await this.expireQuarantine();
    }

    const checkedGateGeneration = taintedCodeWritePending && !inspectionOnly && classification.capabilities.includes("executes_code") && decision.action === "require_approval" && !decision.failClosed
      ? (session.taintedCodeWrite?.generation ?? 1)
      : undefined;
    const toolUseId = hookExec?.toolUseId;
    if (checkedGateGeneration !== undefined && hookExec?.canAsk && toolUseId) {
      this.options.taintStore.updateSession(this.options.sessionId, (state) => {
        if (!state.taintedCodeWrite) return state;
        const now = Date.now();
        const prior = (state.taintedCodeWrite.pendingExecs ?? []).filter((entry) => entry.expiresAt > now);
        const nextExec = {
          id: toolUseId,
          ...(hookExec.command !== undefined ? { command: hookExec.command } : {}),
          tool,
          generation: checkedGateGeneration,
          expiresAt: state.taintedCodeWrite.expiresAt
        };
        return {
          ...state,
          taintedCodeWrite: {
            ...state.taintedCodeWrite,
            pendingExecs: [...prior, nextExec].slice(-32)
          }
        };
      });
    }

    if (hookExec && isNativeFileWriter
      && (approval.approved || hookExec.canAsk && decision.action === "require_approval" && !decision.failClosed)
      && fieldMatches.some(({ field, match }) => (field.role === "body" || tool === "apply_patch" && (field.path === "$.diff" || field.path === "$.command"))
        && !field.path.endsWith(".old_string")
        && match.reason !== "temporal" && match.classes?.includes("untrusted")
        && !this.options.taintStore.get(match.taintId)?.labels.includes("workspace_source"))) {
      const key = this.nativeWriteResultKey(tool, params.arguments, toolUseId);
      if (key) this.options.taintStore.updateSession(this.options.sessionId, (state) => {
        const now = Date.now();
        const pending = (state.pendingTaintedNativeWrites ?? []).filter((entry) => entry.expiresAt > now);
        return {
          ...state,
          pendingTaintedNativeWrites: [...pending, { key, expiresAt: now + this.options.config.taint.exposure.ttlMs }].slice(-64)
        };
      });
    }

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: message.id === undefined ? [] : [
          makeToolErrorResultResponse(
            message.id,
            formatBlockedToolCallResultText(approval.decision, tool, this.options.config.audit.errorVerbosity),
            this.isModernEra(message)
          )
        ],
        toServer: []
      };
    }

    if (classification.capabilities.includes("persists_memory")) {
      for (const taintId of dedupePreservingOrder(allTaintMatches.filter((match) => match.reason !== "temporal").map((match) => match.taintId))) this.options.taintStore.promotePersistent(taintId);
      for (const block of argumentBlocks) {
        const sources = matchText(block.text).filter((match) => match.reason !== "temporal").map((match) => this.options.taintStore.get(match.taintId)).filter((record): record is TaintRecord => Boolean(record));
        if (!sources.length || sources.some((source) => source.persistent && source.payloadHash === sha256(block.text))) continue;
        const source = sources[0]!;
        this.options.taintStore.add({ sessionId: this.options.sessionId, sourceServer: source.sourceServer, sourceTool: source.sourceTool, trust: source.trust, text: block.text, detectorScore: source.detectorScore, labels: source.labels, classes: dedupePreservingOrder<TaintClass>(["untrusted", ...sources.flatMap((record) => record.classes)]), persistent: true, provenanceIds: sources.map((record) => record.id) });
      }
    }

    const writtenFiles = localWorkspaceWrite ? dedupePreservingOrder(protectedPaths.resolved.map((path) => relative(cwd, path.canonical))) : [];
    const nonTemporalRequestMatches = [...matches, ...fieldMatches.map(({ match }) => match), ...inputResponseMatches]
      .filter((match) => match.reason !== "temporal");
    const hasExternalTaint = nonTemporalRequestMatches.some((match) => !this.options.taintStore.get(match.taintId)?.labels.includes("workspace_source"));
    if (localWorkspaceWrite && writtenFiles.length > 0 && hasExternalTaint) {
      this.options.taintStore.updateSession(this.options.sessionId, (state) => {
        const now = Date.now();
        const expiresAt = now + writeGateTtl;
        const generation = (state.taintedCodeWrite?.generation ?? 0) + 1;
        const priorEntries = (state.taintedCodeWrite?.entries ?? (state.taintedCodeWrite?.files ?? []).map((file) => ({
          file,
          generation: state.taintedCodeWrite?.generation ?? Math.max(1, generation - 1),
          expiresAt: state.taintedCodeWrite!.expiresAt
        }))).filter((entry) => entry.expiresAt > now);
        const nextEntries = [...priorEntries, ...writtenFiles.map((file) => ({ file, generation, expiresAt, writtenAt: now }))].slice(-64);
        const merged = dedupePreservingOrder(nextEntries.map((entry) => entry.file)).slice(-10);
        const pendingExecs = state.taintedCodeWrite?.pendingExecs?.filter((entry) => entry.expiresAt > now);
        return {
          ...state,
          taintedCodeWrite: {
            files: merged,
            expiresAt: Math.max(expiresAt, ...nextEntries.map((entry) => entry.expiresAt)),
            generation,
            entries: nextEntries,
            ...(pendingExecs && pendingExecs.length > 0 ? { pendingExecs } : {})
          }
        };
      });
    }

    const approvedGateGeneration = approval.approved ? checkedGateGeneration : undefined;
    if (policyDecision.action === "redact_secrets") {
      const redactedArguments = applyTextTransforms(params.arguments, (text, block) => maskSensitiveText(text, argumentDetectionsByPath.get(pathKey(block))?.spans));
      this.recordPending(message, tool, inspectionOnly, approvedGateGeneration);
      return {
        toClient: [],
        toServer: [{
          ...message,
          params: {
            ...params,
            arguments: redactedArguments
          }
        }]
      };
    }

    this.recordPending(message, tool, inspectionOnly, approvedGateGeneration);
    return { toClient: [], toServer: [message] };
  }

  private async handleToolsListResponse(message: JsonRpcResponse, pending?: PendingClientRequest): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: ToolsListResult }).result;
    const relock = pending?.relock === true;
    const tools = Array.isArray(result.tools) ? result.tools : [];
    const lockChecks = await this.options.lockfile.checkTools(this.options.serverName, tools);
    const contents = tools.flatMap((tool) => extractContent(tool, {
      origin: "tool_metadata",
      sourceServer: this.options.serverName,
      sourceMethod: "tools/list",
      sourceToolOrResource: tool.name,
      trust: this.options.server.trust
    }));
    const { fused: contentFused, detections } = await this.detectContents(visibleMetadataContents(contents));
    const lockStatus = worstLockStatus(lockChecks);
    const review = await this.reviewMetadataSafely(message, tools.map((tool) => ({ name: tool.name, value: tool })), true, startedAt);
    if ("blocked" in review) {
      return review.blocked;
    }
    for (const item of review.items.filter((entry) => entry.detection.score > 0 || entry.detection.labels.length > 0)) {
      detections.push({
        content: { path: `$tool:${item.name}`, kind: "metadata", origin: "tool_metadata", sourceServer: this.options.serverName, sourceMethod: "tools/list", sourceToolOrResource: item.name, trust: this.options.server.trust },
        detection: item.detection
      });
    }
    const fused = review.labels.length > 0 ? fuseDetections(detections.map((entry) => entry.detection)) : contentFused;
    // Detections belong to single tools and are decided per tool below, so one suspicious
    // description withholds that tool instead of the whole server. Fusing every description
    // together also inflated scores: many ordinary "use this tool when" sentences add up.
    const toolDetections = new Map<string, DetectionResult>();
    for (const tool of tools) {
      const own = detections.filter(({ content }) => content.sourceToolOrResource === tool.name).map(({ detection }) => detection);
      if (own.length > 0) toolDetections.set(tool.name, fuseDetections(own));
    }
    const unattributed = detections.filter(({ content }) => !tools.some((tool) => tool.name === content.sourceToolOrResource)).map(({ detection }) => detection);
    const listDetection = unattributed.length > 0 ? fuseDetections(unattributed) : { score: 0, labels: [] as string[] };

    let decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "tools/list",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: listDetection.score,
      labels: listDetection.labels,
      lock_status: lockStatus
    });

    if (relock && lockStatus !== "approved" && (decision.action === "allow" || decision.action === "log_only")) {
      decision = {
        action: "require_approval",
        matchedRuleId: "m5-relock-gate",
        reason: "tools/list_changed: tool metadata drifted from palizade.lock; approval required."
      };
    }

    const approval = await this.maybeApprove(decision, {
      method: "tools/list",
      toolClass: "unknown",
      taintMatches: [],
      summary: `tools/list returned ${tools.length} tool(s); lock status ${lockStatus}; detector score ${fused.score.toFixed(2)}.${relock ? " Triggered by tools/list_changed." : ""}`
    });

    const cacheMetadata = extractCacheMetadata(result);
    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: "tools/list",
      detector: fused,
      lockChecks,
      lockStatus,
      approved: approval.approved,
      payload: result,
      relock,
      cacheMetadata
    });

    if (!approval.approved || decision.action === "block") {
      const error = makeErrorResponse(message.id, -32021, "Palizade blocked tools/list metadata", {
        decision,
        lockChecks,
        detector: fused
      });
      return relock
        ? { toClient: [], toServer: [] }
        : { toClient: [error], toServer: [] };
    }

    const perTool = await this.applyPerToolMetadataDecisions(message, tools, review, startedAt, toolDetections);
    const keptTools = perTool.tools;
    this.registerToolMetadataTaint(keptTools, contents);
    for (const tool of keptTools) {
      this.knownTools.set(tool.name, tool);
    }

    if (relock) {
      return { toClient: [], toServer: [] };
    }

    if (decision.action === "sanitize" || fused.score >= 0.35) {
      const sanitizedTools = keptTools.map((tool) => {
        const toolScore = detections
          .filter(({ content }) => content.sourceToolOrResource === tool.name)
          .reduce((score, item) => Math.max(score, item.detection.score), 0);
        if (toolScore < 0.2) {
          return tool;
        }
        return {
          ...tool,
          description: spotlightText(tool.description ?? "", {
            server: this.options.serverName,
            tool: tool.name,
            taintIds: []
          })
        };
      });
      return { toClient: [{ ...message, result: { ...result, tools: sanitizedTools } }], toServer: [] };
    }

    if (perTool.changed) {
      return { toClient: [{ ...message, result: { ...result, tools: keptTools } }], toServer: [] };
    }
    return { toClient: [message], toServer: [] };
  }

  private async reviewMetadataSafely(
    message: JsonRpcResponse,
    items: MetadataItem[],
    tools: boolean,
    startedAt: number
  ): Promise<MetadataReview | { blocked: EngineOutput }> {
    try {
      return await reviewMetadata(items, {
        serverName: this.options.serverName,
        configuredServers: Object.keys(this.options.config.servers),
        registry: this.toolRegistry,
        config: { ...DEFAULT_METADATA_GUARD_CONFIG, ...this.options.config.metadata },
        tools,
        detect: (text, itemName) => this.options.detector.detect(text, {
          server: this.options.serverName,
          tool: itemName,
          trust: this.options.server.trust,
          surface: "tool_description"
        })
      });
    } catch (error) {
      const decision: PolicyDecision = {
        action: this.options.policy.defaults.on_error,
        reason: `metadata review error: ${error instanceof Error ? error.message : String(error)}`,
        failClosed: true
      };
      await this.auditDecision(message, "response", decision, startedAt, tools ? { method: "tools/list" } : {});
      if (decision.action === "block" || decision.action === "require_approval") {
        return { blocked: { toClient: [makeErrorResponse(message.id, -32028, "Palizade could not verify MCP metadata", { decision })], toServer: [] } };
      }
      return { items: [], labels: [], hiddenUnicode: false, shadowing: false, collision: false };
    }
  }

  private async applyPerToolMetadataDecisions(
    message: JsonRpcResponse,
    tools: McpTool[],
    review: MetadataReview,
    startedAt: number,
    toolDetections: Map<string, DetectionResult> = new Map()
  ): Promise<{ tools: McpTool[]; changed: boolean }> {
    const reviews = new Map(review.items.map((item) => [item.name, item]));
    const kept: McpTool[] = [];
    let changed = false;
    for (const tool of tools) {
      const item = reviews.get(tool.name);
      const contentDetection = toolDetections.get(tool.name);
      const detection = contentDetection && item ? fuseDetections([item.detection, contentDetection]) : contentDetection ?? item?.detection;
      if (!item?.flagged && (detection?.score ?? 0) < 0.35) {
        this.metadataBlockedTools.delete(tool.name);
        kept.push(tool);
        continue;
      }
      const decision = evaluatePolicy(this.options.policy, {
        direction: "response",
        method: "tools/list",
        server: this.options.serverName,
        tool: tool.name,
        trust: this.options.server.trust,
        detector_score: detection?.score ?? 0,
        labels: detection?.labels ?? [],
        tool_shadowing_detected: (item?.shadows.length ?? 0) > 0,
        name_collision_detected: (item?.collidesWith.length ?? 0) > 0,
        hidden_unicode_detected: (item?.hiddenUnicode.count ?? 0) > 0
      });
      if (!item?.flagged && (decision.action === "allow" || decision.action === "log_only" || decision.action === "sanitize")) {
        this.metadataBlockedTools.delete(tool.name);
        kept.push(tool);
        continue;
      }
      const approval = await this.maybeApprove(decision, {
        method: "tools/list",
        tool: tool.name,
        toolClass: "unknown",
        taintMatches: [],
        summary: item ? formatMetadataApprovalSummary(tool.name, item, detection) : `Tool metadata for ${tool.name} reads like instructions to the model (${(detection?.labels ?? []).join(", ")}).`
      });
      await this.auditDecision(message, "response", approval.decision, startedAt, {
        method: "tools/list",
        tool: tool.name,
        ...(detection ? { detector: detection } : {}),
        approved: approval.approved,
        metadataReview: item?.detection.metadata
      });
      if (!approval.approved || decision.action === "block") {
        this.metadataBlockedTools.set(tool.name, approval.decision);
        changed = true;
        continue;
      }
      this.metadataBlockedTools.delete(tool.name);
      if (decision.action === "sanitize" && item && item.hiddenUnicode.count > 0) {
        kept.push(stripHiddenUnicodeDeep(tool));
        changed = true;
        continue;
      }
      kept.push(tool);
    }
    return { tools: kept, changed };
  }

  private async blockToolCallForMetadata(message: JsonRpcRequest, tool: string, decision: PolicyDecision, startedAt: number): Promise<EngineOutput> {
    const blocked: PolicyDecision = { ...decision, action: "block", reason: `tool withheld after metadata review: ${decision.reason}` };
    await this.auditDecision(message, "request", blocked, startedAt, { tool });
    return {
      toClient: message.id === undefined ? [] : [
        makeToolErrorResultResponse(message.id, formatBlockedToolCallResultText(blocked, tool, this.options.config.audit.errorVerbosity), this.isModernEra(message))
      ],
      toServer: []
    };
  }

  private async handleDiscoverMetadataResponse(message: JsonRpcResponse): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: unknown }).result;
    const contents = extractContent(result, {
      origin: "resource_metadata",
      sourceServer: this.options.serverName,
      sourceMethod: "server/discover",
      sourceToolOrResource: "server/discover",
      trust: this.options.server.trust
    });
    const { fused: contentFused } = await this.detectContents(visibleMetadataContents(contents));
    // shortcut: discover shapes without a top-level tools array are scanned but not tool-hashed, extend schema-aware locking when more discover shapes are supported.
    const review = await this.reviewMetadataSafely(message, [{ name: "server/discover", value: result }], false, startedAt);
    if ("blocked" in review) {
      return review.blocked;
    }
    const fused = fuseDetections([contentFused, ...review.items.map((item) => item.detection)]);
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "server/discover",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      tool_shadowing_detected: review.shadowing,
      hidden_unicode_detected: review.hiddenUnicode
    });
    await this.auditDecision(message, "response", decision, startedAt, {
      method: "server/discover",
      detector: fused,
      payload: result,
      metadataReview: review.items[0]?.detection.metadata
    });
    if (decision.action === "block") {
      return { toClient: [makeErrorResponse(message.id, -32029, "Palizade blocked server/discover metadata", { decision, detector: fused })], toServer: [] };
    }
    if (decision.action === "sanitize" && review.hiddenUnicode) {
      return { toClient: [{ ...message, result: stripHiddenUnicodeDeep(result) }], toServer: [] };
    }
    return { toClient: [message], toServer: [] };
  }

  private nativeWriteResultKey(tool: string, input: unknown, toolUseId?: string): string | undefined {
    if (this.options.serverName !== "native-tools" || this.options.server.command !== "native-tools"
      || !NATIVE_WORKSPACE_WRITE_TOOLS.has(tool)) return undefined;
    return this.options.taintStore.destinationKey(stableStringify(["native-write", tool, toolUseId ? ["id", toolUseId] : ["input", input]]));
  }

  async recordToolResult(id: JsonRpcId, tool: string, result: unknown, options: HookToolResultOptions, input?: Record<string, unknown>): Promise<void> {
    const key = this.nativeWriteResultKey(tool, input, options.toolUseId);
    let matchedNativeWrite = false;
    if (key) this.options.taintStore.updateSession(this.options.sessionId, (state) => {
      const pending = (state.pendingTaintedNativeWrites ?? []).filter((entry) => entry.expiresAt > Date.now());
      const index = pending.findIndex((entry) => entry.key === key);
      matchedNativeWrite = index !== -1;
      if (matchedNativeWrite) pending.splice(index, 1);
      return { ...state, pendingTaintedNativeWrites: pending };
    });
    await this.handleToolCallResponse({ jsonrpc: "2.0", id, result }, {
      method: "tools/call",
      tool,
      sensitive: options.sensitivePath === true,
      unmatchedNativeWrite: key !== undefined && !matchedNativeWrite,
      startedAt: Date.now()
    }, options);
  }

  private async handleToolCallResponse(message: JsonRpcResponse, pending: PendingClientRequest, hook?: HookToolResultOptions): Promise<EngineOutput> {
    const startedAt = Date.now();
    const tool = pending.tool ?? "unknown";
    const knownTool = this.knownTools.get(tool);
    const classification = classifyToolDetailed(tool, this.options.server, knownTool);
    const toolClass = classification.toolClass;
    const result = isSuccess(message) ? message.result : message.error;
    // shortcut: input-required gating runs only for tools/call results, extend prompt/resource handlers when those result forms are supported.
    const inputRequiredGate = hook || !isSuccess(message) ? undefined : await this.checkInputRequiredRequests(message, pending, result);
    if (inputRequiredGate) {
      return inputRequiredGate;
    }
    const contentContext = {
      origin: "tool_result",
      sourceServer: this.options.serverName,
      sourceMethod: "tools/call",
      sourceToolOrResource: tool,
      trust: this.options.server.trust
    } as const;
    const contents: ExtractedContent[] = hook?.singleTextBlock && typeof result === "string"
      ? [{ ...contentContext, path: textPathKey([]), kind: "text", text: result }]
      : extractContent(result, contentContext);
    const detectInput: ExtractedContent[] = hook?.destinationOnly && hook.agentResult !== undefined
      ? [{ ...contentContext, path: textPathKey([]), kind: "text", text: hook.agentResult.report }]
      : contents;
    const detectSurface: DetectorContext["surface"] = hook?.workspaceSource && hook?.destinationOnly && hook.agentResult === undefined ? "workspace_read" : "tool_response";
    const { fused, detectionsByPath } = await this.detectContents(detectInput, detectSurface);
    const taintRecords = pending.unmatchedNativeWrite ? [] : this.registerTaintFromContents(tool, classification, contents, fused, pending.sensitive, hook);
    if (fused.score >= this.options.config.taint.quarantine.scoreGte) await this.startQuarantine("High-score tool response.");
    const temporalFromSamplingOrTruncation = Boolean(!pending.unmatchedNativeWrite && !hook?.destinationOnly
      && (hook?.sampled || hook?.truncated || taintRecords.some((record) => record.fingerprint.truncated)));
    if (fused.score >= this.options.config.taint.temporal.detectorScoreGte || temporalFromSamplingOrTruncation) {
      const temporalIds = taintRecords.map((record) => record.id);
      if (temporalIds.length === 0 && temporalFromSamplingOrTruncation) {
        const marker = this.options.taintStore.add({
          sessionId: this.options.sessionId,
          sourceServer: this.options.serverName,
          sourceTool: tool,
          trust: this.options.server.trust,
          text: "",
          detectorScore: fused.score,
          labels: fused.labels,
          classes: ["untrusted"],
          destinationOnly: true
        });
        temporalIds.push(marker.id);
      }
      this.options.taintStore.markTemporal(this.options.sessionId, temporalIds, this.options.config.taint.temporal);
    }
    if (hook?.fileCopies?.length) {
      const copies = hook.fileCopies;
      this.options.taintStore.updateSession(this.options.sessionId, (state) => {
        const gate = state.taintedCodeWrite;
        if (!gate) return state;
        const active = writeEntries(gate).filter(({ expiresAt }) => expiresAt > Date.now());
        const aliases = copiedWriteEntries(active, copies, this.options.server.cwd ?? process.cwd());
        if (aliases.length === 0) return state;
        const entries = [...active, ...aliases].slice(-64);
        return { ...state, taintedCodeWrite: { ...gate, entries, files: dedupePreservingOrder(entries.map(({ file }) => file)).slice(-10) } };
      });
    }
    if (classification.capabilities.includes("executes_code") && !pending.inspectionOnly && !hook?.inspectionOnly) {
      this.options.taintStore.updateSession(this.options.sessionId, (state) => {
        if (!state.taintedCodeWrite) return state;
        const now = Date.now();
        const activeExecs = (state.taintedCodeWrite.pendingExecs ?? []).filter((entry) => entry.expiresAt > now);
        let completedGeneration: number | undefined;
        let remainingExecs = activeExecs;
        if (hook) {
          if (!hook.toolUseId) return state;
          const matchIdx = activeExecs.findIndex((entry) => entry.id === hook.toolUseId && (!hook.command || entry.command === hook.command || entry.command === undefined));
          if (matchIdx < 0) return state;
          completedGeneration = activeExecs[matchIdx]!.generation;
          remainingExecs = activeExecs.filter((_, index) => index !== matchIdx);
        } else {
          if (pending.taintedCodeWriteGeneration === undefined) return state;
          completedGeneration = pending.taintedCodeWriteGeneration;
        }
        const currentGeneration = state.taintedCodeWrite.generation ?? 1;
        const entries = (state.taintedCodeWrite.entries ?? state.taintedCodeWrite.files.map((file) => ({
          file,
          generation: currentGeneration,
          expiresAt: state.taintedCodeWrite!.expiresAt
        }))).filter((entry) => entry.expiresAt > now && entry.generation > completedGeneration);
        if (entries.length === 0 && currentGeneration <= completedGeneration) {
          const { taintedCodeWrite: _cleared, ...rest } = state;
          return rest;
        }
        return {
          ...state,
          taintedCodeWrite: {
            files: entries.length > 0 ? dedupePreservingOrder(entries.map((entry) => entry.file)).slice(-10) : state.taintedCodeWrite.files,
            expiresAt: entries.length > 0 ? Math.max(...entries.map((entry) => entry.expiresAt)) : state.taintedCodeWrite.expiresAt,
            generation: currentGeneration,
            entries,
            ...(remainingExecs.length > 0 ? { pendingExecs: remainingExecs } : {})
          }
        };
      });
    }

    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "tools/call",
      server: this.options.serverName,
      tool,
      tool_class: toolClass,
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: taintRecords.length > 0,
      sensitive_taint: recordsHaveClass(taintRecords, "sensitive"),
      secret_detected: hasSecretLabel(fused.labels),
      pii_detected: hasPiiLabel(fused.labels),
      detector_score: fused.score,
      labels: fused.labels
    });

    const approval = await this.maybeApprove(decision, {
      method: "tools/call",
      tool,
      toolClass,
      classification,
      taintMatches: taintRecords.map((record) => ({ taintId: record.id, reason: "substring" })),
      summary: `${tool} returned ${contents.length} content item(s); detector score ${fused.score.toFixed(2)}.`
    });

    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: "tools/call",
      tool,
      toolClass,
      classification,
      detector: fused,
      taintIds: taintRecords.map((record) => record.id),
      taintClasses: classesFromRecords(taintRecords),
      sensitiveTaint: recordsHaveClass(taintRecords, "sensitive"),
      secretDetected: hasSecretLabel(fused.labels),
      piiDetected: hasPiiLabel(fused.labels),
      approved: approval.approved,
      payload: result
    });

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [
          makeErrorResponse(message.id, -32022, "Palizade blocked MCP tool response", {
            decision,
            detector: fused,
            taintIds: taintRecords.map((record) => record.id)
          })
        ],
        toServer: []
      };
    }

    if (decision.action === "sanitize") {
      return {
        toClient: [transformResponseText(message, (text, block) => isSuccess(message) && !isSpotlightableText(block) ? text : spotlightText(text, {
            server: this.options.serverName,
            tool,
            taintIds: taintRecords.map((record) => record.id)
          }))],
        toServer: []
      };
    }

    if (decision.action === "redact_spans" || decision.action === "redact_secrets") {
      return {
        toClient: [transformResponseText(message, (text, block) => redactSpans(text, detectionsByPath.get(pathKey(block))?.spans))],
        toServer: []
      };
    }

    return { toClient: [message], toServer: [] };
  }

  private async checkInputRequiredRequests(
    message: JsonRpcResponse,
    pending: PendingClientRequest,
    result: unknown
  ): Promise<EngineOutput | undefined> {
    const inputRequests = inspectInputRequired(result);
    if (!inputRequests) {
      return undefined;
    }
    const startedAt = Date.now();
    const tool = pending.tool ?? "unknown";
    const allowlist = this.learnedEgress.allowlist(this.options.config.egress.allowlist);
    const failures: string[] = [];
    const decisions: PolicyDecision[] = [];

    for (const [key, request] of Object.entries(inputRequests)) {
      const method = typeof request.method === "string" ? request.method : "unknown";
      const params = (request.params ?? {}) as { mode?: string; url?: string; requestedSchema?: unknown };

      if (method === "sampling/createMessage" || method.startsWith("sampling/")) {
        const decision = evaluatePolicy(this.options.policy, {
          direction: "request",
          method: "sampling/createMessage",
          server: this.options.serverName,
          trust: this.options.server.trust,
          tool_class: "unknown",
          capabilities: ["invokes_model"]
        });
        decisions.push(decision);
        if (decision.action === "block") {
          failures.push(`Sampling request '${key}' was blocked: ${decision.reason}`);
          continue;
        }
        if (decision.action === "require_approval") {
          const approval = await this.maybeApprove(decision, {
            method: "sampling/createMessage",
            toolClass: "unknown",
            classification: { toolClass: "unknown", capabilities: ["invokes_model"], reasons: ["sampling"] },
            taintMatches: [],
            summary: `${this.options.serverName} requested model access through an input_required result (${key}).`
          });
          if (!approval.approved) {
            failures.push(`Sampling request '${key}' was not approved.`);
          }
        }
        continue;
      }

      if (method.startsWith("elicitation/")) {
        if (params.mode !== "url") {
          if (elicitationRequestsSensitiveFields(params.requestedSchema)) {
            failures.push(`Elicitation request '${key}' uses form mode to request sensitive fields (passwords, API keys, tokens, payment data); the spec forbids this.`);
            continue;
          }
        } else if (typeof params.url === "string") {
          const urlFields = extractArgumentFields({ url: params.url }, tool, this.options.server.argumentRoles?.[tool]);
          const entries = destinationEntries(urlFields);
          if (entries.length > 0 && !destinationsAllowed(entries, allowlist)) {
            failures.push(`Elicitation URL '${params.url}' is not in the egress allowlist.`);
            continue;
          }
          const urlTaint = this.options.taintStore.match(this.options.sessionId, params.url, {
            fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax,
            classes: ["untrusted"],
            destinationRole: true
          }).filter((match) => match.reason !== "temporal");
          if (urlTaint.length > 0) {
            failures.push(`Elicitation URL '${params.url}' came from untrusted content.`);
            continue;
          }
        }
        const decision = evaluatePolicy(this.options.policy, {
          direction: "request",
          method: "elicitation/create",
          server: this.options.serverName,
          trust: this.options.server.trust,
          tool_class: "unknown",
          capabilities: ["user_interaction"]
        });
        decisions.push(decision);
        if (decision.action === "block") {
          failures.push(`Elicitation request '${key}' was blocked: ${decision.reason}`);
          continue;
        }
        if (decision.action === "require_approval") {
          const approval = await this.maybeApprove(decision, {
            method: "elicitation/create",
            toolClass: "unknown",
            classification: { toolClass: "unknown", capabilities: ["user_interaction"], reasons: ["elicitation"] },
            taintMatches: [],
            summary: `${this.options.serverName} requested user input through an input_required result (${key}).`
          });
          if (!approval.approved) {
            failures.push(`Elicitation request '${key}' was not approved.`);
          }
        }
        continue;
      }

      if (method === "roots/list") {
        continue;
      }

      failures.push(`Input request '${key}' uses unsupported method '${method}'.`);
    }

    if (failures.length > 0) {
      const decision: PolicyDecision = {
        action: "block",
        matchedRuleId: "m5-input-required-gate",
        reason: failures.join("; ")
      };
      await this.auditDecision(message, "response", decision, startedAt, {
        method: "tools/call",
        tool,
        metadata: { inputRequests: Object.keys(inputRequests), failures }
      });
      return {
        toClient: [makeToolErrorResultResponse(
          message.id,
          failures.length === 1 ? `Palizade blocked an input request: ${failures[0]}` : `Palizade blocked ${failures.length} input requests:\n${failures.map((failure) => `- ${failure}`).join("\n")}`,
          true
        )],
        toServer: []
      };
    }

    for (const decision of decisions) {
      await this.auditDecision(message, "response", decision, startedAt, {
        method: "tools/call",
        tool,
        metadata: { inputRequests: Object.keys(inputRequests) }
      });
    }
    return undefined;
  }

  private async handleServerInitiatedRequest(message: JsonRpcRequest): Promise<EngineOutput> {
    const startedAt = Date.now();
    const isSampling = message.method === "sampling/createMessage" || message.method.startsWith("sampling/");
    const isElicitation = message.method.startsWith("elicitation/");
    const isSafeServerRequest = ["roots/list", "ping"].includes(message.method);
    if (!isSampling && !isElicitation && isSafeServerRequest) {
      return { toClient: [message], toServer: [] };
    }
    if (!isSampling && !isElicitation) {
      const decision: PolicyDecision = {
        action: "block",
        reason: `non-allowlisted server-initiated request: ${message.method}`
      };
      await this.auditDecision(message, "request", decision, startedAt, { payload: message.params });
      return {
        toClient: [],
        toServer: message.id === undefined ? [] : [
          makeErrorResponse(message.id, -32024, "Palizade blocked non-allowlisted server request", { decision })
        ]
      };
    }

    const contents = extractContent(message.params, {
      origin: isSampling ? "sampling_request" : "elicitation_request",
      sourceServer: this.options.serverName,
      sourceMethod: message.method,
      trust: this.options.server.trust
    });
    const { fused: detection } = await this.detectContents(contents);
    const argumentText = contentText(contents) || flattenArguments(message.params);
    const decision = evaluatePolicy(this.options.policy, {
      direction: "request",
      method: message.method,
      server: this.options.serverName,
      trust: this.options.server.trust,
      tool_class: "unknown",
      capabilities: isSampling ? ["invokes_model"] : ["user_interaction"],
      detector_score: detection.score,
      labels: detection.labels,
      argument_text: argumentText
    });

    const approval = await this.maybeApprove(decision, {
      method: message.method,
      toolClass: "unknown",
      classification: { toolClass: "unknown", capabilities: isSampling ? ["invokes_model"] : ["user_interaction"], reasons: [isSampling ? "sampling" : "elicitation"] },
      taintMatches: [],
      summary: `${this.options.serverName} requested model access via ${message.method}.`
    });

    await this.auditDecision(message, "request", approval.decision, startedAt, {
      detector: detection,
      approved: approval.approved,
      payload: message.params
    });

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [],
        toServer: message.id === undefined ? [] : [
          makeErrorResponse(message.id, -32023, "Palizade blocked server-initiated model access", {
            decision,
            detector: detection
          })
        ]
      };
    }

    return { toClient: [message], toServer: [] };
  }

  private async handleServerNotification(message: JsonRpcMessage): Promise<EngineOutput> {
    const startedAt = Date.now();
    const request = message as JsonRpcRequest;
    const method = request.method;
    const rawParams = request.params;
    const inspectableParams = method === "notifications/progress" && rawParams && typeof rawParams === "object" && !Array.isArray(rawParams)
      ? (({ progressToken: _ignored, ...rest }) => rest)(rawParams as Record<string, unknown>)
      : rawParams;
    const contents = extractContent(inspectableParams, {
      origin: "notification",
      sourceServer: this.options.serverName,
      sourceMethod: method,
      trust: this.options.server.trust
    });
    const classification: ToolClassification = { toolClass: "source", capabilities: ["reads_untrusted_content"], reasons: ["notification"] };
    const { fused, detectionsByPath } = contents.length > 0
      ? await this.detectContents(contents)
      : { fused: { score: 0, labels: [] }, detectionsByPath: new Map<string, DetectionResult>() };
    const taintRecords = contents.length > 0
      ? this.registerTaintFromContents(method, classification, contents, fused)
      : [];
    if (fused.score >= this.options.config.taint.quarantine.scoreGte) {
      await this.startQuarantine("High-score server notification.");
    }
    if (fused.score >= this.options.config.taint.temporal.detectorScoreGte && taintRecords.length > 0) {
      this.options.taintStore.markTemporal(this.options.sessionId, taintRecords.map((record) => record.id), this.options.config.taint.temporal);
    }

    const toServer: JsonRpcMessage[] = [];
    let defaultReason = `notification forwarded: ${method}`;
    if (isToolsListChanged(message)) {
      const relockId = `palizade-relock-${randomUUID()}`;
      this.pendingClient.set(relockId, { method: "tools/list", startedAt, relock: true });
      toServer.push({
        jsonrpc: "2.0",
        id: relockId,
        method: "tools/list",
        params: this.isModernEra(message) ? { _meta: { [PROTOCOL_VERSION_META_KEY]: "2026-07-28" } } : {}
      });
      defaultReason = "tools/list_changed: re-locking and re-verifying tool metadata against palizade.lock.";
    }

    const evaluated = evaluatePolicy(this.options.policy, {
      direction: "response",
      method,
      server: this.options.serverName,
      tool_class: "source",
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: taintRecords.length > 0,
      sensitive_taint: recordsHaveClass(taintRecords, "sensitive"),
      secret_detected: hasSecretLabel(fused.labels),
      pii_detected: hasPiiLabel(fused.labels),
      detector_score: fused.score,
      labels: fused.labels
    });
    // Presets like strict default to require_approval; only enforce explicit notification rules.
    const decision: PolicyDecision = !evaluated.matchedRuleId && evaluated.action === "require_approval"
      ? { action: "allow", reason: defaultReason }
      : evaluated.matchedRuleId
        ? evaluated
        : { ...evaluated, reason: defaultReason };
    const approval = await this.maybeApprove(decision, {
      method,
      toolClass: "source",
      classification,
      taintMatches: taintRecords.map((record) => ({ taintId: record.id, reason: "substring" })),
      summary: `${method} carried ${contents.length} content item(s); detector score ${fused.score.toFixed(2)}.`
    });
    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method,
      toolClass: "source",
      classification,
      detector: fused,
      taintIds: taintRecords.map((record) => record.id),
      taintClasses: classesFromRecords(taintRecords),
      sensitiveTaint: recordsHaveClass(taintRecords, "sensitive"),
      secretDetected: hasSecretLabel(fused.labels),
      piiDetected: hasPiiLabel(fused.labels),
      approved: approval.approved,
      payload: rawParams
    });

    if (!approval.approved || decision.action === "block") {
      return { toClient: [], toServer };
    }
    if (decision.action === "sanitize" && rawParams !== undefined) {
      return {
        toClient: [{
          ...request,
          params: applyTextTransforms(rawParams, (text) => spotlightText(text, {
            server: this.options.serverName,
            tool: method,
            taintIds: taintRecords.map((record) => record.id)
          }))
        }],
        toServer
      };
    }
    if ((decision.action === "redact_spans" || decision.action === "redact_secrets") && rawParams !== undefined) {
      return {
        toClient: [{
          ...request,
          params: applyTextTransforms(rawParams, (text, block) => redactSpans(text, detectionsByPath.get(pathKey(block))?.spans))
        }],
        toServer
      };
    }
    return { toClient: [message], toServer };
  }

  private isModernEra(message?: JsonRpcMessage): boolean {
    const era = message ? detectEra(message) : undefined;
    if (era !== undefined) return era === "2026-07-28";
    return this.clientEra === "2026-07-28" || this.serverEra === "2026-07-28" || this.options.server.protocolVersion === "2026-07-28";
  }

  private async handleServerDiscoverResponse(message: JsonRpcResponse): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: unknown }).result;
    const tools = Array.isArray((result as { tools?: unknown })?.tools)
      ? ((result as { tools: McpTool[] }).tools as McpTool[])
      : [];
    const lockChecks = tools.length > 0
      ? await this.options.lockfile.checkTools(this.options.serverName, tools)
      : [];
    const contents = extractContent(result, {
      origin: "tool_metadata",
      sourceServer: this.options.serverName,
      sourceMethod: "server/discover",
      trust: this.options.server.trust
    });
    const { fused } = await this.detectContents(contents);
    const lockStatus = tools.length > 0 ? worstLockStatus(lockChecks) : "unknown";
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "server/discover",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      lock_status: lockStatus
    });
    const approval = await this.maybeApprove(decision, {
      method: "server/discover",
      toolClass: "unknown",
      taintMatches: [],
      summary: `server/discover returned ${tools.length} tool(s); lock status ${lockStatus}; detector score ${fused.score.toFixed(2)}.`
    });
    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: "server/discover",
      detector: fused,
      lockChecks,
      lockStatus,
      approved: approval.approved,
      payload: result
    });
    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [makeErrorResponse(message.id, -32021, "Palizade blocked server/discover metadata", { decision, lockChecks, detector: fused })],
        toServer: []
      };
    }
    for (const tool of tools) {
      this.knownTools.set(tool.name, tool);
    }
    return { toClient: [message], toServer: [] };
  }

  private registerTaint(tool: string, toolClass: ToolClass, blocks: TextBlock[], detection: DetectionResult): TaintRecord[] {
    const untrusted = this.options.server.trust !== "trusted" || toolClass === "source" || detection.score >= this.options.config.taint.suspiciousScore;
    const sensitive = this.isSensitiveOrigin(tool) || hasSecretLabel(detection.labels) || hasPiiLabel(detection.labels);
    const classes = taintClasses({ untrusted, sensitive });
    if (classes.length === 0) {
      return [];
    }
    return blocks
      .filter((block) => block.text.trim().length >= 8 || extractDestinationObservables(block.text).length > 0)
      .map((block) => this.options.taintStore.add({
        sessionId: this.options.sessionId,
        sourceServer: this.options.serverName,
        sourceTool: tool,
        trust: this.options.server.trust,
        text: block.text,
        detectorScore: detection.score,
        labels: detection.labels,
        classes
      }));
  }

  /**
   * A server that is not trusted wrote its own tool descriptions, so values in them (a path, a
   * key, a recipient, a url) are untrusted data: a poisoned description can tell the model to use
   * them with another tool. Recorded as taint without marking the session as having seen
   * untrusted content, since every session lists tools.
   */
  private registerToolMetadataTaint(tools: McpTool[], contents: ExtractedContent[]): void {
    if (!this.options.config.taint.toolMetadata || this.options.server.trust === "trusted") return;
    const kept = new Set(tools.map((tool) => tool.name));
    for (const content of contents) {
      const text = content.text?.trim() ?? "";
      if (text.length < 8 || !content.sourceToolOrResource || !kept.has(content.sourceToolOrResource)) continue;
      this.options.taintStore.add({
        sessionId: this.options.sessionId,
        sourceServer: this.options.serverName,
        sourceTool: `tools/list:${content.sourceToolOrResource}`,
        trust: this.options.server.trust,
        text,
        detectorScore: 0,
        labels: ["tool_metadata"],
        classes: ["untrusted"]
      });
    }
  }

  private registerTaintFromContents(sourceName: string, classification: ToolClassification, contents: ExtractedContent[], detection: DetectionResult, sensitivePath = false, hook?: HookToolResultOptions): TaintRecord[] {
    const suspicious = detection.score >= this.options.config.taint.suspiciousScore;
    const resultAgentId = hook?.agentResult?.id;
    const agentState = resultAgentId ? this.options.taintStore.getSession(this.options.sessionId) : undefined;
    const agentUntrusted = resultAgentId && agentState?.untrustedAgents?.includes(resultAgentId);
    const agentSensitive = resultAgentId && agentState?.sensitiveAgents?.includes(resultAgentId);
    const agentReport = hook?.agentResult?.report;
    const agentTextTainted = agentReport && hook?.destinationOnly && !agentUntrusted && !suspicious &&
      this.options.taintStore.match(this.options.sessionId, agentReport).some(({ reason }) => reason !== "temporal");
    const destinationOnly = hook?.destinationOnly && !agentUntrusted && !agentTextTainted;
    const highRiskSource = hook ? !destinationOnly : this.options.server.trust === "untrusted" || classification.toolClass === "source" || classification.capabilities.includes("reads_untrusted_content");
    const untrustedAgentResult = hook?.agentResult !== undefined && highRiskSource;
    const detectedSensitive = hasSecretLabel(detection.labels) || hasPiiLabel(detection.labels);
    const sensitiveSource = sensitivePath || agentSensitive || detectedSensitive || classification.capabilities.includes("reads_sensitive_data");
    const isWorkspaceSource = Boolean(hook?.workspaceSource && destinationOnly && !suspicious && !sensitiveSource);
    const recordLabels = isWorkspaceSource ? dedupePreservingOrder([...detection.labels, "workspace_source"]) : detection.labels;
    const taintContents = destinationOnly && !suspicious && !sensitiveSource && agentReport !== undefined
      ? contents.map((content) => ({ ...content, text: agentReport })) : contents;
    const minLength = hook && (sensitivePath || detectedSensitive || hook.singleTextBlock) ? 1 : 8;
    const provenanceCache = new Map<string, TaintRecord[]>();
    const persistentSources = (text: string): TaintRecord[] => {
      const candidate = destinationOnly && agentReport !== undefined ? agentReport : text;
      if (!provenanceCache.has(candidate)) provenanceCache.set(candidate, this.options.taintStore.match(this.options.sessionId, candidate, { persistentOnly: true }).filter((match) => match.reason !== "temporal").map((match) => this.options.taintStore.get(match.taintId)).filter((record): record is TaintRecord => Boolean(record?.persistent)));
      return provenanceCache.get(candidate)!;
    };
    const externalSampledOrTruncated = Boolean(!destinationOnly && (hook?.sampled || hook?.truncated));
    const hasText = taintContents.some((content) => Boolean(content.text));
    if (sensitivePath || agentSensitive || untrustedAgentResult || externalSampledOrTruncated || hasText) this.options.taintStore.updateSession(this.options.sessionId, (previous) => {
      const state = expireExposure(previous, this.options.config.taint.exposure.ttlMs);
      const untrusted = externalSampledOrTruncated || untrustedAgentResult || (hasText && (highRiskSource || suspicious || taintContents.some((content) => persistentSources(content.text ?? "").length > 0)));
      const sensitive = sensitiveSource || taintContents.some((content) => this.isSensitiveOrigin(sourceName, content) || persistentSources(content.text ?? "").some((record) => record.classes.includes("sensitive")));
      const agentId = hook?.agentId;
      return {
        ...state,
        ...(agentId && untrusted ? { untrustedAgents: rememberAgent(state.untrustedAgents, agentId) } : {}),
        ...(agentId && sensitive ? { sensitiveAgents: rememberAgent(state.sensitiveAgents, agentId) } : {}),
        seenUntrusted: state.seenUntrusted || untrusted,
        seenSensitive: state.seenSensitive || sensitive,
        exposureExpiresAt: untrusted || sensitive ? Date.now() + this.options.config.taint.exposure.ttlMs : state.exposureExpiresAt
      };
    });
    const records = taintContents
      .filter((content) => content.text && content.kind !== "binary" && (content.text.trim().length >= minLength ||
        SHORT_SENSITIVE_SHELL_COMMAND.test(content.text.trim()) ||
        extractAtomicTokens(content.text).some((token) => isMatchableToken(normalizeText(token))) ||
        extractDestinationObservables(content.text).length > 0))
      .flatMap((content) => {
        const provenance = persistentSources(content.text ?? "");
        const untrusted = provenance.length > 0 || highRiskSource || suspicious;
        const sensitive = sensitiveSource || provenance.some((record) => record.classes.includes("sensitive")) || this.isSensitiveOrigin(sourceName, content);
        const classes = taintClasses({ untrusted, sensitive });
        if (classes.length === 0) {
          return [];
        }
        return [this.options.taintStore.add({
          sessionId: this.options.sessionId,
          sourceServer: provenance[0]?.sourceServer ?? this.options.serverName,
          sourceTool: provenance[0]?.sourceTool ?? content.sourceToolOrResource ?? sourceName,
          trust: this.options.server.trust,
          text: content.text ?? "",
          detectorScore: detection.score,
          labels: recordLabels,
          classes,
          persistent: provenance.length > 0,
          provenanceIds: dedupePreservingOrder(provenance.flatMap((record) => [record.id, ...(record.provenanceIds ?? [])]))
        })];
      });
    const lightDestinations = destinationOnly && !suspicious ? extractDestinationObservables(contentText(taintContents), true) : [];
    const observables = dedupePreservingOrder([...lightDestinations, ...(hook?.sampledDestinations ?? [])]);
    if (observables.length > 0) {
      records.push(this.options.taintStore.add({
        sessionId: this.options.sessionId,
        sourceServer: this.options.serverName,
        sourceTool: sourceName,
        trust: this.options.server.trust,
        text: observables.join("\n"),
        detectorScore: detection.score,
        labels: recordLabels,
        classes: taintClasses({ untrusted: true, sensitive: sensitiveSource }),
        destinationOnly: true,
        destinations: observables
      }));
    }
    return records;
  }

  private async handleDescriptorListResponse(
    message: JsonRpcResponse,
    bucket: "prompts" | "resources" | "resourceTemplates",
    origin: ContentOrigin,
    resultKey: string,
    nameOf: (item: unknown) => string
  ): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: Record<string, unknown> }).result;
    const descriptors = Array.isArray(result[resultKey]) ? result[resultKey] as unknown[] : [];
    const lockChecks = await this.options.lockfile.checkDescriptors(this.options.serverName, bucket, descriptors, nameOf);
    const contents = descriptors.flatMap((descriptor) => extractContent(descriptor, {
      origin,
      sourceServer: this.options.serverName,
      sourceMethod: bucket === "prompts" ? "prompts/list" : bucket === "resources" ? "resources/list" : "resources/templates/list",
      sourceToolOrResource: nameOf(descriptor),
      trust: this.options.server.trust
    }));
    const { fused: contentFused } = await this.detectContents(visibleMetadataContents(contents));
    const review = await this.reviewMetadataSafely(message, descriptors.map((descriptor) => ({ name: nameOf(descriptor), value: descriptor })), false, startedAt);
    if ("blocked" in review) {
      return review.blocked;
    }
    const fused = review.labels.length > 0 ? fuseDetections([contentFused, ...review.items.map((item) => item.detection)]) : contentFused;
    const lockStatus = worstLockStatus(lockChecks);
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: bucket === "prompts" ? "prompts/list" : bucket === "resources" ? "resources/list" : "resources/templates/list",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      lock_status: lockStatus,
      tool_shadowing_detected: review.shadowing,
      hidden_unicode_detected: review.hiddenUnicode
    });
    const approval = await this.maybeApprove(decision, {
      method: bucket,
      toolClass: "unknown",
      classification: { toolClass: "unknown", capabilities: ["reads_untrusted_content"], reasons: ["prompt"] },
      taintMatches: [],
      summary: `${bucket} returned ${descriptors.length} descriptor(s); lock status ${lockStatus}; detector score ${fused.score.toFixed(2)}.`
    });
    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: bucket === "prompts" ? "prompts/list" : bucket === "resources" ? "resources/list" : "resources/templates/list",
      detector: fused,
      lockChecks,
      lockStatus,
      approved: approval.approved,
      payload: result
    });
    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [makeErrorResponse(message.id, -32025, `Palizade blocked ${bucket} metadata`, { decision, detector: fused, lockChecks })],
        toServer: []
      };
    }
    if (decision.action === "sanitize" && review.hiddenUnicode) {
      return { toClient: [{ ...message, result: { ...result, [resultKey]: stripHiddenUnicodeDeep(descriptors) } }], toServer: [] };
    }
    return { toClient: [message], toServer: [] };
  }

  private async handleGenericContentResponse(message: JsonRpcResponse, pending: PendingClientRequest, origin: ContentOrigin): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = isSuccess(message) ? message.result : message.error;
    const contents = extractContent(result, {
      origin,
      sourceServer: this.options.serverName,
      sourceMethod: pending.method,
      trust: this.options.server.trust
    });
    const { fused, detectionsByPath } = await this.detectContents(contents);
    const classification: ToolClassification = { toolClass: "source", capabilities: ["reads_untrusted_content"], reasons: ["resource"] };
    const taintRecords = this.registerTaintFromContents(pending.method, classification, contents, fused);
    if (fused.score >= this.options.config.taint.quarantine.scoreGte) await this.startQuarantine("High-score source response.");
    if (fused.score >= this.options.config.taint.temporal.detectorScoreGte || taintRecords.some((record) => record.fingerprint.truncated)) {
      this.options.taintStore.markTemporal(this.options.sessionId, taintRecords.map((record) => record.id), this.options.config.taint.temporal);
    }
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: pending.method,
      server: this.options.serverName,
      tool_class: "source",
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: taintRecords.length > 0,
      sensitive_taint: recordsHaveClass(taintRecords, "sensitive"),
      secret_detected: hasSecretLabel(fused.labels),
      pii_detected: hasPiiLabel(fused.labels),
      detector_score: fused.score,
      labels: fused.labels
    });
    const approval = await this.maybeApprove(decision, {
      method: pending.method,
      toolClass: "source",
      classification,
      taintMatches: taintRecords.map((record) => ({ taintId: record.id, reason: "substring" })),
      summary: `${pending.method} returned ${contents.length} content item(s); detector score ${fused.score.toFixed(2)}.`
    });
    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: pending.method,
      toolClass: "source",
      classification,
      detector: fused,
      taintIds: taintRecords.map((record) => record.id),
      taintClasses: classesFromRecords(taintRecords),
      sensitiveTaint: recordsHaveClass(taintRecords, "sensitive"),
      secretDetected: hasSecretLabel(fused.labels),
      piiDetected: hasPiiLabel(fused.labels),
      approved: approval.approved,
      payload: result
    });
    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [makeErrorResponse(message.id, -32026, `Palizade blocked ${pending.method} content`, { decision, detector: fused })],
        toServer: []
      };
    }
    if (decision.action === "sanitize") {
      return {
        toClient: [transformResponseText(message, (text, block) => isSuccess(message) && !isSpotlightableText(block) ? text : spotlightText(text, {
            server: this.options.serverName,
            tool: pending.method,
            taintIds: taintRecords.map((record) => record.id)
          }))],
        toServer: []
      };
    }
    if (decision.action === "redact_spans" || decision.action === "redact_secrets") {
      return {
        toClient: [transformResponseText(message, (text, block) => redactSpans(text, detectionsByPath.get(pathKey(block))?.spans))],
        toServer: []
      };
    }
    return { toClient: [message], toServer: [] };
  }

  private async handleInitializeResponse(message: JsonRpcResponse): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: unknown }).result;
    const capabilityCheck = await this.options.lockfile.checkCapabilities(this.options.serverName, result);
    const contents = extractContent(result, {
      origin: "resource_metadata",
      sourceServer: this.options.serverName,
      sourceMethod: "initialize",
      sourceToolOrResource: "serverInfo",
      trust: this.options.server.trust
    });
    const { fused } = await this.detectContents(contents);
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "initialize",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      lock_status: capabilityCheck.status
    });
    await this.auditDecision(message, "response", decision, startedAt, {
      method: "initialize",
      detector: fused,
      lockChecks: [capabilityCheck],
      lockStatus: capabilityCheck.status,
      payload: result
    });
    if (decision.action === "block") {
      return {
        toClient: [makeErrorResponse(message.id, -32027, "Palizade blocked initialize metadata", { decision, detector: fused, capabilityCheck })],
        toServer: []
      };
    }
    return { toClient: [message], toServer: [] };
  }

  private async detectContents(
    contents: ExtractedContent[],
    defaultSurface: DetectorContext["surface"] = "tool_response"
  ): Promise<{
    fused: DetectionResult;
    detections: Array<{ content: ExtractedContent; detection: DetectionResult }>;
    detectionsByPath: Map<string, DetectionResult>;
  }> {
    const detections = await Promise.all(contents
      .filter((content) => content.text && content.kind !== "binary")
      .map(async (content) => ({
        content,
        detection: await this.options.detector.detect(content.text ?? "", {
          server: this.options.serverName,
          tool: content.sourceToolOrResource,
          trust: this.options.server.trust,
          surface: content.origin === "tool_metadata" ? "tool_description" : content.origin === "sampling_request" ? "sampling" : defaultSurface
        })
      })));
    const fused = fuseDetections(detections.map((entry) => entry.detection));
    return {
      fused,
      detections,
      detectionsByPath: new Map(detections.map((entry) => [entry.content.path, entry.detection]))
    };
  }

  private async maybeApprove(
    decision: PolicyDecision,
    input: {
      method: string;
      tool?: string;
      toolClass: ToolClass;
      classification?: ToolClassification;
      taintMatches: Array<TaintMatch | { taintId: string; reason: string }>;
      summary: string;
      rememberDestinations?: string[];
      trustSessionDestinations?: string[];
      details?: Record<string, unknown>;
    }
  ): Promise<{ approved: boolean; decision: PolicyDecision }> {
    if (decision.action !== "require_approval") {
      return { approved: decision.action !== "block", decision };
    }
    const approval = await this.options.approvals.requestApproval(createApprovalRequest({
      sessionId: this.options.sessionId,
      server: this.options.serverName,
      tool: input.tool,
      method: input.method,
      reason: decision.reason,
      taintIds: input.taintMatches.map((match) => match.taintId),
      summary: input.summary,
      timeoutMs: this.options.config.approvals.timeoutMs,
      details: {
        ...input.details,
        toolClass: input.toolClass,
        capabilities: input.classification?.capabilities,
        matchedRuleId: decision.matchedRuleId,
        allowAlways: !this.options.sealedLearnedEgress && Boolean(input.rememberDestinations?.length),
        allowSession: Boolean(input.trustSessionDestinations?.length)
      }
    }));
    const always = approval.approved && approval.remember === "always" ? input.rememberDestinations : undefined;
    const sealed = Boolean(this.options.sealedLearnedEgress);
    if (!sealed && always?.length) this.learnedEgress.remember(always);
    const session = approval.approved && (approval.remember === "session" || (sealed && always?.length)) ? input.trustSessionDestinations : undefined;
    if (session?.length) {
      const grant = (existing: Iterable<string>) => {
        const trustedDestinations = new Set([...existing, ...session]);
        if (trustedDestinations.size > 1024) throw new Error("Session destination grant limit exceeded");
        return trustedDestinations;
      };
      if (this.sealedSessionDestinations) this.sealedSessionDestinations = grant(this.sealedSessionDestinations);
      else this.options.taintStore.updateSession(this.options.sessionId, (state) => ({ ...state, trustedDestinations: [...grant(state.trustedDestinations)] }));
    }
    return {
      approved: approval.approved,
      decision: {
        ...decision,
        reason: `${decision.reason}; approval ${approval.approved ? "granted" : "denied"} (${formatApprovalDecisionReason(approval)})${sealed && session?.length ? "; destination grant is session only while sealed" : ""}`
      }
    };
  }

  private recordPending(message: JsonRpcRequest, tool?: string, inspectionOnly = false, taintedCodeWriteGeneration?: number): void {
    if (message.id === undefined) {
      return;
    }
    this.pendingClient.set(message.id, {
      method: message.method,
      tool,
      ...(inspectionOnly ? { inspectionOnly: true } : {}),
      ...(taintedCodeWriteGeneration !== undefined ? { taintedCodeWriteGeneration } : {}),
      sensitive: this.isSensitiveOrigin(tool ?? message.method) || extractArgumentFields((message.params as ToolsCallParams | undefined)?.arguments).some((field) => field.role === "file_path" && this.options.server.sensitivePathPatterns.some((pattern) => new RegExp(pattern, "iu").test(field.text))),
      startedAt: Date.now()
    });
  }

  private async startQuarantine(reason: string): Promise<void> {
    const previous = this.options.taintStore.getSession(this.options.sessionId).quarantine;
    const config = this.options.config.taint.quarantine;
    this.options.taintStore.updateSession(this.options.sessionId, (state) => ({ ...state, quarantine: { expiresAt: Date.now() + config.ttlMs, remainingTurns: config.turns } }));
    if (!previous) await this.auditSessionEvent("start", reason);
  }

  private async expireQuarantine(): Promise<void> {
    const quarantine = this.options.taintStore.getSession(this.options.sessionId).quarantine;
    if (!quarantine || (quarantine.expiresAt > Date.now() && quarantine.remainingTurns > 0)) return;
    this.options.taintStore.updateSession(this.options.sessionId, (state) => ({ ...state, quarantine: undefined }));
    await this.auditSessionEvent("end", "Session quarantine expired.");
  }

  private async auditSessionEvent(event: string, reason: string): Promise<void> {
    await this.options.audit.write({ session: this.options.sessionId, profile_id: this.options.config.taint.profileId, run_id: process.env.PALIZADE_RUN_ID, direction: "internal", method: `session/quarantine/${event}`, action: "log_only", reason });
  }

  private async auditDecision(
    message: JsonRpcMessage,
    direction: "request" | "response" | "internal",
    decision: PolicyDecision,
    startedAt: number,
    extra: {
      tool?: string;
      toolClass?: ToolClass;
      classification?: ToolClassification;
      detector?: DetectionResult;
      taintMatches?: Array<TaintMatch | { taintId: string; reason: string }>;
      taintIds?: string[];
      lockChecks?: ToolLockCheck[];
      lockStatus?: string;
      approved?: boolean;
      payload?: unknown;
      method?: string;
      argumentRoles?: string[];
      taintedArgumentRoles?: string[];
      taintClasses?: TaintClass[];
      destination?: DestinationSummary;
      sensitiveTaint?: boolean;
      secretDetected?: boolean;
      piiDetected?: boolean;
      redacted?: boolean;
      relock?: boolean;
      cacheMetadata?: { ttlMs?: number; cacheScope?: string } | undefined;
      metadata?: Record<string, unknown>;
      metadataReview?: unknown;
    } = {}
  ): Promise<void> {
    await this.options.audit.write({
      profile_id: this.options.config.taint.profileId,
      scope_id: auditScopeId(this.options.config.taint.scope, this.options.config.taint.profileId, process.env.PALIZADE_RUN_ID, this.options.sessionId),
      run_id: process.env.PALIZADE_RUN_ID,
      session: this.options.sessionId,
      server: this.options.serverName,
      tool: extra.tool,
      direction,
      method: extra.method ?? (isRequest(message) ? message.method : undefined),
      taint_ids: dedupePreservingOrder(extra.taintIds ?? extra.taintMatches?.map((match) => match.taintId) ?? []),
      detector: {
        score: extra.detector?.score ?? 0,
        labels: extra.detector?.labels ?? []
      },
      matched_rule: decision.matchedRuleId || decision.matchedRuleName ? {
        id: decision.matchedRuleId,
        name: decision.matchedRuleName
      } : undefined,
      action: decision.action,
      reason: decision.reason,
      latency_ms: Date.now() - startedAt,
      payload: (extra.taintIds?.length || extra.taintMatches?.some((match) => match.reason !== "temporal")) && extra.payload !== undefined ? "[REDACTED:tainted-content]" : scrubAuditPayload(extra.payload),
      metadata: {
        toolClass: extra.toolClass,
        capabilities: extra.classification?.capabilities,
        classificationReasons: extra.classification?.reasons,
        lockChecks: extra.lockChecks,
        lockStatus: extra.lockStatus,
        approved: extra.approved,
        argumentRoles: extra.argumentRoles,
        taintedArgumentRoles: extra.taintedArgumentRoles,
        taintClasses: extra.taintClasses,
        destination: extra.destination,
        sensitiveTaint: extra.sensitiveTaint,
        secretDetected: extra.secretDetected,
        piiDetected: extra.piiDetected,
        redacted: extra.redacted,
        relock: extra.relock,
        cacheMetadata: extra.cacheMetadata,
        era: this.serverEra ?? this.clientEra,
        ...extra.metadata,
        matchReasons: dedupePreservingOrder(extra.taintMatches?.map((match) => match.reason) ?? []),
        metadataReview: extra.metadataReview,
        taintSources: (extra.taintIds ?? extra.taintMatches?.map((match) => match.taintId) ?? []).map((id) => this.options.taintStore.get(id)).filter((record): record is TaintRecord => Boolean(record)).map((record) => ({ id: record.id, server: record.sourceServer, tool: record.sourceTool, persistent: record.persistent ?? false, provenanceIds: record.provenanceIds ?? [] }))
      }
    });
  }

  private isSensitiveOrigin(sourceName: string, content?: ExtractedContent): boolean {
    if (this.options.server.sensitive) {
      return true;
    }
    if (this.options.server.sensitiveTools[sourceName] === true) {
      return true;
    }
    if (content?.sourceToolOrResource && this.options.server.sensitiveTools[content.sourceToolOrResource] === true) {
      return true;
    }
    const searchable = [
      sourceName,
      content?.sourceToolOrResource,
      content?.path,
      typeof content?.rawValue === "string" ? content.rawValue : undefined
    ].filter((value): value is string => Boolean(value));
    return this.options.server.sensitivePathPatterns.some((pattern) => searchable.some((value) => new RegExp(pattern, "iu").test(value)));
  }
}

function isLoopbackUrl(text: string): boolean {
  try {
    const host = canonicalHost(new URL(text).hostname);
    return /(?:^|\.)localhost(?:\.localdomain)?$/u.test(host) || /^(?:127\.|\[::1\]$|\[::ffff:7f[\da-f]{2}:)/u.test(host);
  } catch { return false; }
}

function pathKey(block: TextBlock): string {
  return textPathKey(block.path, block.key);
}

function taintClasses(input: { untrusted: boolean; sensitive: boolean }): TaintClass[] {
  const classes: TaintClass[] = [];
  if (input.untrusted) {
    classes.push("untrusted");
  }
  if (input.sensitive) {
    classes.push("sensitive");
  }
  return classes;
}

function recordsHaveClass(records: TaintRecord[], taintClass: TaintClass): boolean {
  return records.some((record) => record.classes.includes(taintClass));
}

function classesFromRecords(records: TaintRecord[]): TaintClass[] {
  return dedupePreservingOrder(records.flatMap((record) => record.classes));
}

function transformResponseText(message: JsonRpcResponse, transform: Parameters<typeof applyTextTransforms>[1]): JsonRpcResponse {
  return isSuccess(message)
    ? { ...message, result: applyTextTransforms(message.result, transform) }
    : { ...message, error: applyTextTransforms(message.error, transform) as JsonRpcFailure["error"] };
}

function rememberAgent(ids: string[] = [], agentId: string): string[] {
  return [...ids.filter((id) => id !== agentId), agentId].slice(-32);
}

function classesFromMatches(matches: Array<TaintMatch | { taintId: string; reason: string; classes?: TaintClass[] | undefined }>): TaintClass[] {
  return dedupePreservingOrder(matches.flatMap((match) => match.classes ?? []));
}

function formatToolCallApprovalSummary(input: {
  tool: string;
  toolClass: ToolClass;
  capabilities: string[];
  taintMatches: Array<TaintMatch | { taintId: string; reason: string; classes?: TaintClass[] | undefined }>;
  taintedArgumentRoles: string[];
  destination: DestinationSummary;
  taintStore: TaintStore;
}): string {
  const taintIds = dedupePreservingOrder(input.taintMatches.map((match) => match.taintId));
  const capabilities = input.capabilities.join(",") || "no capabilities";
  const roles = input.taintedArgumentRoles.length > 0 ? input.taintedArgumentRoles.join(",") : "none detected";
  const sources = summarizeTaintSources(taintIds, input.taintStore);
  const destination = summarizeApprovalDestination(input.destination);
  return [
    `${input.tool} (${input.toolClass}; ${capabilities}) wants to run with ${taintIds.length} taint match(es).`,
    `Tainted argument role(s): ${roles}.`,
    sources.length > 0 ? `Tainted source(s): ${sources.join("; ")}.` : undefined,
    destination ? `Destination: ${destination}.` : undefined
  ].filter(Boolean).join(" ");
}

/** Hidden characters in metadata are judged by the metadata review, which also decodes TAG payloads. */
function visibleMetadataContents(contents: ExtractedContent[]): ExtractedContent[] {
  return contents.map((content) => content.text ? { ...content, text: stripHiddenUnicode(content.text) } : content);
}

function formatMetadataApprovalSummary(tool: string, item: MetadataReview["items"][number], detection?: DetectionResult): string {
  return [
    `Tool metadata for ${tool} was flagged.`,
    detection && detection.labels.length > 0 ? `Signals: ${detection.labels.join(", ")}.` : undefined,
    item.hiddenUnicode.count > 0 ? `Hidden characters: ${item.hiddenUnicode.count} (${item.hiddenUnicode.codePoints.join(", ")}).` : undefined,
    item.shadows.length > 0 ? `Mentions tools of other servers: ${item.shadows.map((entry) => `${entry.server}/${entry.tool}`).join(", ")}.` : undefined,
    item.collidesWith.length > 0 ? `Name also exposed by: ${item.collidesWith.join(", ")}.` : undefined,
    item.dangerousDefaults.length > 0 ? `Dangerous defaults at: ${item.dangerousDefaults.map((entry) => entry.path).join(", ")}.` : undefined
  ].filter(Boolean).join(" ");
}

function summarizeTaintSources(taintIds: string[], taintStore: TaintStore): string[] {
  return dedupePreservingOrder(taintIds.flatMap((taintId) => {
    const record = taintStore.get(taintId);
    if (!record) {
      return [];
    }
    const classes = record.classes.length > 0 ? record.classes.join("+") : "unclassified";
    return [`${record.sourceServer}/${record.sourceTool} (${record.trust}, ${classes})`];
  }));
}

function summarizeApprovalDestination(destination: DestinationSummary): string | undefined {
  const parts = [
    destination.hosts.length > 0 ? `hosts=${destination.hosts.join(",")}` : undefined,
    destination.emailRecipients.length > 0 ? `emails=${destination.emailRecipients.join(",")}` : undefined,
    destination.allowlistConfigured ? `allowlist=${destination.allowed ? "matched" : "not matched"}` : undefined
  ].filter(Boolean);
  return parts.length > 0 ? parts.join("; ") : undefined;
}

function summarizeDestinations(argumentFields: ArgumentField[], allowlist: PalizadeConfig["egress"]["allowlist"], tainted: (value: string) => boolean): DestinationSummary {
  const hosts = dedupePreservingOrder(argumentFields.flatMap((field) => hostsFromField(field)));
  const emails = dedupePreservingOrder(argumentFields
    .filter((field) => field.role === "email_recipient")
    .map((field) => field.text.toLowerCase()));
  const entries = destinationEntries(argumentFields);
  const allowlistConfigured = allowlist.hosts.length > 0 || allowlist.emails.length > 0 || allowlist.destinations.length > 0;
  return {
    allowed: !allowlistConfigured || destinationsAllowed(entries, allowlist),
    allowlistConfigured,
    hosts,
    emailRecipients: emails.map((email) => tainted(email) ? "[REDACTED:tainted-recipient]" : maskSensitiveValueForMetadata(email)),
    destinationCount: entries.length
  };
}

function hostsFromField(field: ArgumentField): string[] {
  if (field.role === "hostname") {
    return [canonicalHost(field.text)].filter(Boolean);
  }
  if (field.role !== "url") {
    return [];
  }
  try {
    return [canonicalHost(new URL(field.text).hostname)].filter(Boolean);
  } catch {
    return [];
  }
}

function maskSensitiveValueForMetadata(value: string): string {
  const [local, domain] = value.split("@");
  if (!local || !domain) {
    return "[REDACTED:destination]";
  }
  return `${local.slice(0, 1) || "*"}***@${domain}`;
}

function scrubAuditPayload(value: unknown): unknown {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return maskKnownSensitiveText(value);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  try {
    return applyTextTransforms(value, (text) => maskKnownSensitiveText(text));
  } catch {
    return "[payload omitted: audit masking failed]";
  }
}

function worstLockStatus(checks: ToolLockCheck[]): "approved" | "new" | "changed" | "missing" | "unknown" {
  if (checks.length === 0) return "unknown";
  if (checks.some((check) => check.status === "changed")) return "changed";
  if (checks.some((check) => check.status === "new")) return "new";
  if (checks.some((check) => check.status === "missing")) return "missing";
  return "approved";
}

function inspectInputRequired(result: unknown): Record<string, { method?: unknown; params?: unknown }> | undefined {
  if (!result || typeof result !== "object") {
    return undefined;
  }
  const record = result as Record<string, unknown>;
  if (record.resultType !== "input_required") {
    return undefined;
  }
  const inputRequests = record.inputRequests;
  if (!inputRequests || typeof inputRequests !== "object" || Array.isArray(inputRequests)) {
    return undefined;
  }
  const output: Record<string, { method?: unknown; params?: unknown }> = {};
  for (const [key, value] of Object.entries(inputRequests)) {
    if (value && typeof value === "object") {
      const request = value as Record<string, unknown>;
      output[key] = { method: request.method, params: request.params };
    }
  }
  return Object.keys(output).length > 0 ? output : undefined;
}

function elicitationRequestsSensitiveFields(requestedSchema: unknown): boolean {
  if (!requestedSchema || typeof requestedSchema !== "object") {
    return false;
  }
  const searchable = JSON.stringify(requestedSchema);
  const properties = (requestedSchema as Record<string, unknown>).properties;
  if (properties && typeof properties === "object") {
    for (const [name, schema] of Object.entries(properties)) {
      if (SENSITIVE_FIELD_NAME_RE.test(name)) {
        return true;
      }
      if (schema && typeof schema === "object") {
        const descriptor = schema as Record<string, unknown>;
        const strings = [descriptor.title, descriptor.description, descriptor.default].filter((value): value is string => typeof value === "string");
        if (strings.some((value) => SENSITIVE_FIELD_NAME_RE.test(value))) {
          return true;
        }
      }
    }
  }
  return SENSITIVE_FIELD_NAME_RE.test(searchable);
}

function extractCacheMetadata(result: unknown): { ttlMs?: number; cacheScope?: string } | undefined {
  if (!result || typeof result !== "object") {
    return undefined;
  }
  const record = result as Record<string, unknown>;
  const meta = record._meta;
  const scope = typeof record.cacheScope === "string"
    ? record.cacheScope
    : meta && typeof meta === "object" && typeof (meta as Record<string, unknown>).cacheScope === "string"
      ? (meta as Record<string, unknown>).cacheScope as string
      : undefined;
  const ttl = typeof record.ttlMs === "number"
    ? record.ttlMs
    : meta && typeof meta === "object" && typeof (meta as Record<string, unknown>).ttlMs === "number"
      ? (meta as Record<string, unknown>).ttlMs as number
      : undefined;
  if (scope === undefined && ttl === undefined) {
    return undefined;
  }
  return {
    ...(scope !== undefined ? { cacheScope: scope } : {}),
    ...(ttl !== undefined ? { ttlMs: ttl } : {})
  };
}

function descriptorName(item: unknown, fallback: string): string {
  if (item && typeof item === "object") {
    const record = item as Record<string, unknown>;
    for (const key of ["name", "uri", "uriTemplate", "title", "id"]) {
      if (typeof record[key] === "string" && record[key].length > 0) {
        return record[key];
      }
    }
  }
  return `${fallback}:${JSON.stringify(item).slice(0, 80)}`;
}

function formatBlockedToolCallResultText(decision: PolicyDecision, tool: string, verbose: boolean): string {
  if (!verbose) {
    return "Palizade blocked this tool call. This action was prevented by your local Palizade security policy.";
  }
  const rule = decision.matchedRuleId ?? "policy-default";
  const reason = scrubClientBlockText(trimTrailingPeriod(decision.reason));
  return `Palizade blocked this tool call. Rule: ${rule}. Reason: ${reason}. Tool: ${tool}. This action was prevented by your local Palizade security policy.`;
}

function formatApprovalDecisionReason(approval: ApprovalDecision): string {
  const details = [
    approval.reason,
    approval.approvalUrl ? `approval page: ${approval.approvalUrl}` : undefined,
    approval.approvalFile ? `approval URL file: ${approval.approvalFile}` : undefined
  ].filter(Boolean);
  return details.join("; ");
}

function scrubClientBlockText(text: string): string {
  return text.replace(/\btaint_[A-Za-z0-9-]+\b/gu, "[taint-id]");
}

function trimTrailingPeriod(text: string): string {
  return text.endsWith(".") ? text.slice(0, -1) : text;
}

function dedupePreservingOrder<T extends string>(values: T[]): T[] {
  return [...new Set(values)];
}

function isSafeWorkspaceCwd(cwd: string): boolean {
  try {
    const fold = (value: string) => {
      const stripped = process.platform === "win32" ? value.replace(/^\\\\\?\\UNC\\/iu, "\\\\").replace(/^\\\\\?\\/u, "") : value;
      return process.platform === "win32" || process.platform === "darwin" ? stripped.toLowerCase() : stripped;
    };
    const realCwd = fold(realpathSync.native(cwd));
    const realHome = fold(realpathSync.native(homedir()));
    if (dirname(realCwd) === realCwd) return false;
    const relToHome = relative(realCwd, realHome);
    return relToHome !== "" && (relToHome.startsWith("..") || isAbsolute(relToHome));
  } catch {
    return false;
  }
}

function shellReferencesManagedSeal(fields: ArgumentField[], cwd: string): boolean {
  const managed = process.env.PALIZADE_SEAL_PATH;
  if (!managed) return false;
  const resolved = resolveArgumentPath(managed, cwd);
  const fold = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const targets = new Set<string>();
  for (const candidate of [managed, resolved.logical, resolved.canonical]) {
    if (!candidate) continue;
    targets.add(fold(candidate));
    targets.add(fold(candidate.replaceAll("\\", "/")));
  }
  const shellText = fields
    .filter((field) => field.role === "shell_command")
    .map((field) => {
      const folded = fold(field.text);
      return `${folded}\n${folded.replaceAll("\\", "/")}`;
    })
    .join("\n");
  return shellText.length > 0 && [...targets].some((target) => shellText.includes(target));
}

function isExecutableOrBuildFile(filePath: string): boolean {
  const name = basename(filePath).toLowerCase();
  if (EXECUTABLE_OR_BUILD_BASENAMES.has(name) ||
      /^(?:docker-)?compose.*\.ya?ml$/u.test(name) ||
      /^tsconfig(?:\..+)?\.json$/u.test(name) ||
      /^(?:vitest|jest|eslint)\.config\.[^\\/]+$/u.test(name) ||
      /\.pth$/u.test(name) && /(?:^|[\\/])(?:site|dist)-packages[\\/]/iu.test(filePath)) return true;
  const dot = name.lastIndexOf(".");
  return dot >= 0 && EXECUTABLE_OR_BUILD_EXTENSIONS.has(name.slice(dot));
}

type WriteGate = NonNullable<SessionState["taintedCodeWrite"]>;

function writeEntries(gate: WriteGate): NonNullable<WriteGate["entries"]> {
  return gate.entries ?? gate.files.map((file) => ({ file, generation: gate.generation ?? 1, expiresAt: gate.expiresAt }));
}

function writtenBasename(path: string): string {
  const name = basename(path.replace(/\\/gu, "/"));
  return process.platform === "win32" || process.platform === "darwin" ? name.toLowerCase() : name;
}

function copiedWriteEntries(entries: ReturnType<typeof writeEntries>, copies: ShellAnalysis["copies"], workspace: string) {
  const aliases: ReturnType<typeof writeEntries> = [];
  const tracked = new Map(entries.map((entry) => [writtenBasename(entry.file), entry]));
  for (const copy of copies) {
    const original = tracked.get(writtenBasename(copy.source));
    if (!original) continue;
    const source = resolveArgumentPath(copy.source, copy.cwd);
    const target = resolveArgumentPath(copy.path, copy.cwd);
    if (!isWorkspacePath(source, workspace) || !isWorkspacePath(target, workspace)) continue;
    const file = relative(workspace, target.canonical);
    const alias = { ...original, file };
    tracked.set(writtenBasename(file), alias);
    aliases.push(alias);
  }
  return aliases;
}

function auditScopeId(scope: PalizadeConfig["taint"]["scope"], profileId: string, runId: string | undefined, sessionId: string): string {
  if (scope === "process") {
    return `process:${sessionId}`;
  }
  if (scope === "external_run_id") {
    return `run:${runId ?? sessionId}`;
  }
  return `profile:${profileId}`;
}
