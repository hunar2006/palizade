import type { ApprovalProvider } from "@palisade/approvals";
import { createApprovalRequest } from "@palisade/approvals";
import type { AuditLogger } from "@palisade/audit";
import type { DetectionResult, Detector } from "@palisade/detectors";
import { fuseDetections } from "@palisade/detectors";
import { evaluatePolicy, type PolicyDecision, type PolicyDocument, type ToolClass } from "@palisade/policy";
import type { TaintMatch, TaintRecord, TaintStore } from "@palisade/taint";
import { extractArgumentFields, argumentRolesSummary } from "./arguments.js";
import { classifyToolDetailed, type ToolClassification } from "./classifier.js";
import type { PalisadeConfig, ServerConfig } from "./config.js";
import { contentText, extractContent, type ContentOrigin, type ExtractedContent } from "./content.js";
import type { LockfileStore, ToolLockCheck } from "./lockfile.js";
import {
  isRequest,
  isSuccess,
  makeErrorResponse,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpTool,
  type ToolsCallParams,
  type ToolsListResult
} from "./mcp.js";
import { applyTextTransforms, extractTextBlocks, flattenArguments, redactSpans, spotlightText, type TextBlock } from "./text.js";

export interface InterceptionEngineOptions {
  config: PalisadeConfig;
  serverName: string;
  server: ServerConfig;
  sessionId: string;
  policy: PolicyDocument;
  detector: Detector;
  taintStore: TaintStore;
  audit: AuditLogger;
  approvals: ApprovalProvider;
  lockfile: LockfileStore;
}

export interface EngineOutput {
  toClient: JsonRpcMessage[];
  toServer: JsonRpcMessage[];
}

interface PendingClientRequest {
  method: string;
  tool?: string | undefined;
  startedAt: number;
}

export class InterceptionEngine {
  private readonly pendingClient = new Map<string, PendingClientRequest>();
  private readonly knownTools = new Map<string, McpTool>();

  constructor(private readonly options: InterceptionEngineOptions) {}

  async handleClientMessage(message: JsonRpcMessage): Promise<EngineOutput> {
    if (!isRequest(message)) {
      return { toClient: [], toServer: [message] };
    }

    if (message.method === "initialize") {
      this.recordPending(message);
      await this.auditDecision(message, "request", { action: "allow", reason: "initialize forwarded" }, Date.now());
      return { toClient: [], toServer: [message] };
    }

    if (message.method === "tools/call") {
      return this.handleToolCallRequest(message);
    }

    this.recordPending(message);
    return { toClient: [], toServer: [message] };
  }

  async handleServerMessage(message: JsonRpcMessage): Promise<EngineOutput> {
    if (isRequest(message)) {
      return this.handleServerInitiatedRequest(message);
    }

    if (!isSuccess(message)) {
      return { toClient: [message], toServer: [] };
    }

    const pending = this.pendingClient.get(String(message.id));
    if (!pending) {
      return { toClient: [message], toServer: [] };
    }
    this.pendingClient.delete(String(message.id));

    if (pending.method === "tools/list") {
      return this.handleToolsListResponse(message);
    }
    if (pending.method === "tools/call") {
      return this.handleToolCallResponse(message, pending);
    }
    if (pending.method === "resources/list") {
      return this.handleDescriptorListResponse(message, "resources", "resource_metadata", "resources", (item) => descriptorName(item, "resource"));
    }
    if (pending.method === "resources/templates/list") {
      return this.handleDescriptorListResponse(message, "resourceTemplates", "resource_metadata", "resourceTemplates", (item) => descriptorName(item, "resourceTemplate"));
    }
    if (pending.method === "resources/read") {
      return this.handleGenericContentResponse(message, pending, "resource_content");
    }
    if (pending.method === "prompts/list") {
      return this.handleDescriptorListResponse(message, "prompts", "prompt_metadata", "prompts", (item) => descriptorName(item, "prompt"));
    }
    if (pending.method === "prompts/get") {
      return this.handleGenericContentResponse(message, pending, "prompt_content");
    }
    if (pending.method === "initialize") {
      return this.handleInitializeResponse(message);
    }

    return { toClient: [message], toServer: [] };
  }

  private async handleToolCallRequest(message: JsonRpcRequest): Promise<EngineOutput> {
    const startedAt = Date.now();
    const params = (message.params ?? {}) as ToolsCallParams;
    const tool = params.name ?? "unknown";
    const knownTool = this.knownTools.get(tool);
    const classification = classifyToolDetailed(tool, this.options.server, knownTool);
    const toolClass = classification.toolClass;
    const argumentText = flattenArguments(params.arguments);
    const argumentFields = extractArgumentFields(params.arguments);
    const matches = this.options.taintStore.match(this.options.sessionId, argumentText, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax
    });
    const fieldMatches = argumentFields.flatMap((field) => this.options.taintStore.match(this.options.sessionId, field.text, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax
    }).map((match) => ({ field, match })));
    const taintedArgumentRoles = [...new Set(fieldMatches.map(({ field }) => field.role))];
    const temporal = matches.some((match) => match.reason === "temporal") || this.options.taintStore.hasTemporal(this.options.sessionId);

    const decision = evaluatePolicy(this.options.policy, {
      direction: "request",
      method: message.method,
      server: this.options.serverName,
      tool,
      tool_class: toolClass,
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: matches.length > 0 || fieldMatches.length > 0,
      temporal_taint: temporal,
      argument_text: argumentText,
      argument_roles: argumentRolesSummary(argumentFields),
      tainted_argument_roles: taintedArgumentRoles
    });

    const approval = await this.maybeApprove(decision, {
      method: message.method,
      tool,
      toolClass,
      classification,
      taintMatches: [...matches, ...fieldMatches.map(({ match }) => match)],
      summary: `${tool} (${toolClass}; ${classification.capabilities.join(",") || "no capabilities"}) wants to run with ${matches.length + fieldMatches.length} taint match(es).`
    });

    await this.auditDecision(message, "request", approval.decision, startedAt, {
      tool,
      toolClass,
      classification,
      taintMatches: [...matches, ...fieldMatches.map(({ match }) => match)],
      approved: approval.approved
    });

    this.options.taintStore.consumeTurn(this.options.sessionId);

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: message.id === undefined ? [] : [
          makeErrorResponse(message.id, -32020, "Palisade blocked MCP tool call", {
            decision,
            taint: matches,
            taintedArgumentRoles
          })
        ],
        toServer: []
      };
    }

    this.recordPending(message, tool);
    return { toClient: [], toServer: [message] };
  }

  private async handleToolsListResponse(message: JsonRpcResponse): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: ToolsListResult }).result;
    const tools = Array.isArray(result.tools) ? result.tools : [];
    const lockChecks = await this.options.lockfile.checkTools(this.options.serverName, tools);
    const contents = tools.flatMap((tool) => extractContent(tool, {
      origin: "tool_metadata",
      sourceServer: this.options.serverName,
      sourceMethod: "tools/list",
      sourceToolOrResource: tool.name,
      trust: this.options.server.trust
    }));
    const { fused, detections } = await this.detectContents(contents);
    const lockStatus = worstLockStatus(lockChecks);

    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: "tools/list",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      lock_status: lockStatus
    });

    const approval = await this.maybeApprove(decision, {
      method: "tools/list",
      toolClass: "unknown",
      taintMatches: [],
      summary: `tools/list returned ${tools.length} tool(s); lock status ${lockStatus}; detector score ${fused.score.toFixed(2)}.`
    });

    await this.auditDecision(message, "response", approval.decision, startedAt, {
      method: "tools/list",
      detector: fused,
      lockChecks,
      lockStatus,
      approved: approval.approved,
      payload: result
    });

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [
          makeErrorResponse(message.id, -32021, "Palisade blocked tools/list metadata", {
            decision,
            lockChecks,
            detector: fused
          })
        ],
        toServer: []
      };
    }

    for (const tool of tools) {
      this.knownTools.set(tool.name, tool);
    }

    if (decision.action === "sanitize" || fused.score >= 0.35) {
      const sanitizedTools = tools.map((tool) => {
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

    return { toClient: [message], toServer: [] };
  }

  private async handleToolCallResponse(message: JsonRpcResponse, pending: PendingClientRequest): Promise<EngineOutput> {
    const startedAt = Date.now();
    const tool = pending.tool ?? "unknown";
    const knownTool = this.knownTools.get(tool);
    const classification = classifyToolDetailed(tool, this.options.server, knownTool);
    const toolClass = classification.toolClass;
    const result = (message as { result: unknown }).result;
    const contents = extractContent(result, {
      origin: "tool_result",
      sourceServer: this.options.serverName,
      sourceMethod: "tools/call",
      sourceToolOrResource: tool,
      trust: this.options.server.trust
    });
    const { fused, detectionsByPath } = await this.detectContents(contents);
    const taintRecords = this.registerTaintFromContents(tool, classification, contents, fused);
    if (fused.score >= this.options.config.taint.temporal.detectorScoreGte) {
      this.options.taintStore.markTemporal(this.options.sessionId, taintRecords.map((record) => record.id), this.options.config.taint.temporal);
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
      approved: approval.approved,
      payload: result
    });

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [
          makeErrorResponse(message.id, -32022, "Palisade blocked MCP tool response", {
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
        toClient: [{
          ...message,
          result: applyTextTransforms(result, (text) => spotlightText(text, {
            server: this.options.serverName,
            tool,
            taintIds: taintRecords.map((record) => record.id)
          }))
        }],
        toServer: []
      };
    }

    if (decision.action === "redact_spans") {
      return {
        toClient: [{
          ...message,
          result: applyTextTransforms(result, (text, block) => redactSpans(text, detectionsByPath.get(pathKey(block))?.spans))
        }],
        toServer: []
      };
    }

    return { toClient: [message], toServer: [] };
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
          makeErrorResponse(message.id, -32024, "Palisade blocked non-allowlisted server request", { decision })
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
      classification: { toolClass: "unknown", capabilities: isSampling ? ["invokes_model"] : ["user_interaction"] },
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
          makeErrorResponse(message.id, -32023, "Palisade blocked server-initiated model access", {
            decision,
            detector: detection
          })
        ]
      };
    }

    return { toClient: [message], toServer: [] };
  }

  private registerTaint(tool: string, toolClass: ToolClass, blocks: TextBlock[], detection: DetectionResult): TaintRecord[] {
    const shouldTaint = this.options.server.trust !== "trusted" || toolClass === "source" || detection.score >= this.options.config.taint.suspiciousScore;
    if (!shouldTaint) {
      return [];
    }
    return blocks
      .filter((block) => block.text.trim().length >= 8)
      .map((block) => this.options.taintStore.add({
        sessionId: this.options.sessionId,
        sourceServer: this.options.serverName,
        sourceTool: tool,
        trust: this.options.server.trust,
        text: block.text,
        detectorScore: detection.score,
        labels: detection.labels
      }));
  }

  private registerTaintFromContents(sourceName: string, classification: ToolClassification, contents: ExtractedContent[], detection: DetectionResult): TaintRecord[] {
    const highRiskSource = this.options.server.trust === "untrusted" || classification.toolClass === "source" || classification.capabilities.includes("reads_untrusted_content");
    const shouldTaint = highRiskSource || detection.score >= this.options.config.taint.suspiciousScore;
    if (!shouldTaint) {
      return [];
    }
    return contents
      .filter((content) => content.text && content.text.trim().length >= 8 && content.kind !== "binary")
      .map((content) => this.options.taintStore.add({
        sessionId: this.options.sessionId,
        sourceServer: this.options.serverName,
        sourceTool: content.sourceToolOrResource ?? sourceName,
        trust: this.options.server.trust,
        text: content.text ?? "",
        detectorScore: detection.score,
        labels: detection.labels
      }));
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
    const { fused } = await this.detectContents(contents);
    const lockStatus = worstLockStatus(lockChecks);
    const decision = evaluatePolicy(this.options.policy, {
      direction: "response",
      method: bucket === "prompts" ? "prompts/list" : bucket === "resources" ? "resources/list" : "resources/templates/list",
      server: this.options.serverName,
      trust: this.options.server.trust,
      detector_score: fused.score,
      labels: fused.labels,
      lock_status: lockStatus
    });
    const approval = await this.maybeApprove(decision, {
      method: bucket,
      toolClass: "unknown",
      classification: { toolClass: "unknown", capabilities: ["reads_untrusted_content"] },
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
        toClient: [makeErrorResponse(message.id, -32025, `Palisade blocked ${bucket} metadata`, { decision, detector: fused, lockChecks })],
        toServer: []
      };
    }
    return { toClient: [message], toServer: [] };
  }

  private async handleGenericContentResponse(message: JsonRpcResponse, pending: PendingClientRequest, origin: ContentOrigin): Promise<EngineOutput> {
    const startedAt = Date.now();
    const result = (message as { result: unknown }).result;
    const contents = extractContent(result, {
      origin,
      sourceServer: this.options.serverName,
      sourceMethod: pending.method,
      trust: this.options.server.trust
    });
    const { fused, detectionsByPath } = await this.detectContents(contents);
    const classification: ToolClassification = { toolClass: "source", capabilities: ["reads_untrusted_content"] };
    const taintRecords = this.registerTaintFromContents(pending.method, classification, contents, fused);
    if (fused.score >= this.options.config.taint.temporal.detectorScoreGte) {
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
      approved: approval.approved,
      payload: result
    });
    if (!approval.approved || decision.action === "block") {
      return {
        toClient: [makeErrorResponse(message.id, -32026, `Palisade blocked ${pending.method} content`, { decision, detector: fused })],
        toServer: []
      };
    }
    if (decision.action === "sanitize") {
      return {
        toClient: [{
          ...message,
          result: applyTextTransforms(result, (text) => spotlightText(text, {
            server: this.options.serverName,
            tool: pending.method,
            taintIds: taintRecords.map((record) => record.id)
          }))
        }],
        toServer: []
      };
    }
    if (decision.action === "redact_spans") {
      return {
        toClient: [{
          ...message,
          result: applyTextTransforms(result, (text, block) => redactSpans(text, detectionsByPath.get(pathKey(block))?.spans))
        }],
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
        toClient: [makeErrorResponse(message.id, -32027, "Palisade blocked initialize metadata", { decision, detector: fused, capabilityCheck })],
        toServer: []
      };
    }
    return { toClient: [message], toServer: [] };
  }

  private async detectContents(contents: ExtractedContent[]): Promise<{
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
          surface: content.origin === "tool_metadata" ? "tool_description" : content.origin === "sampling_request" ? "sampling" : "tool_response"
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
        toolClass: input.toolClass,
        capabilities: input.classification?.capabilities,
        matchedRuleId: decision.matchedRuleId
      }
    }));
    return {
      approved: approval.approved,
      decision: {
        ...decision,
        reason: `${decision.reason}; approval ${approval.approved ? "granted" : "denied"} (${approval.reason})`
      }
    };
  }

  private recordPending(message: JsonRpcRequest, tool?: string): void {
    if (message.id === undefined) {
      return;
    }
    this.pendingClient.set(String(message.id), {
      method: message.method,
      tool,
      startedAt: Date.now()
    });
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
    } = {}
  ): Promise<void> {
    await this.options.audit.write({
      profile_id: this.options.config.taint.profileId,
      scope_id: auditScopeId(this.options.config.taint.scope, this.options.config.taint.profileId, process.env.PALISADE_RUN_ID, this.options.sessionId),
      run_id: process.env.PALISADE_RUN_ID,
      session: this.options.sessionId,
      server: this.options.serverName,
      tool: extra.tool,
      direction,
      method: extra.method ?? (isRequest(message) ? message.method : undefined),
      taint_ids: extra.taintIds ?? extra.taintMatches?.map((match) => match.taintId) ?? [],
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
      payload: extra.payload,
      metadata: {
        toolClass: extra.toolClass,
        capabilities: extra.classification?.capabilities,
        lockChecks: extra.lockChecks,
        lockStatus: extra.lockStatus,
        approved: extra.approved
      }
    });
  }
}

function pathKey(block: TextBlock): string {
  return block.path.join(".");
}

function worstLockStatus(checks: ToolLockCheck[]): "approved" | "new" | "changed" | "missing" | "unknown" {
  if (checks.length === 0) return "unknown";
  if (checks.some((check) => check.status === "changed")) return "changed";
  if (checks.some((check) => check.status === "new")) return "new";
  if (checks.some((check) => check.status === "missing")) return "missing";
  return "approved";
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

function auditScopeId(scope: PalisadeConfig["taint"]["scope"], profileId: string, runId: string | undefined, sessionId: string): string {
  if (scope === "process") {
    return `process:${sessionId}`;
  }
  if (scope === "external_run_id") {
    return `run:${runId ?? sessionId}`;
  }
  return `profile:${profileId}`;
}
