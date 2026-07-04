import type { ApprovalProvider } from "@palizade/approvals";
import { createApprovalRequest } from "@palizade/approvals";
import type { AuditLogger } from "@palizade/audit";
import type { DetectionResult, Detector } from "@palizade/detectors";
import { fuseDetections, hasPiiLabel, hasSecretLabel, maskKnownSensitiveText, maskSensitiveText } from "@palizade/detectors";
import { evaluatePolicy, type PolicyDecision, type PolicyDocument, type ToolClass } from "@palizade/policy";
import type { TaintClass, TaintMatch, TaintRecord, TaintStore } from "@palizade/taint";
import { extractArgumentFields, argumentRolesSummary, type ArgumentField } from "./arguments.js";
import { classifyToolDetailed, type ToolClassification } from "./classifier.js";
import type { PalizadeConfig, ServerConfig } from "./config.js";
import { contentText, extractContent, type ContentOrigin, type ExtractedContent } from "./content.js";
import type { LockfileStore, ToolLockCheck } from "./lockfile.js";
import {
  isRequest,
  isSuccess,
  makeErrorResponse,
  makeToolErrorResultResponse,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpTool,
  type ToolsCallParams,
  type ToolsListResult
} from "./mcp.js";
import { applyTextTransforms, extractTextBlocks, flattenArguments, redactSpans, spotlightText, type TextBlock } from "./text.js";

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
    const matches = this.options.taintStore.match(this.options.sessionId, argumentText, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax
    });
    const fieldMatches = argumentFields.flatMap((field) => this.options.taintStore.match(this.options.sessionId, field.text, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax
    }).map((match) => ({ field, match })));
    const sensitiveMatches = this.options.taintStore.match(this.options.sessionId, argumentText, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax,
      classes: ["sensitive"]
    });
    const sensitiveFieldMatches = argumentFields.flatMap((field) => this.options.taintStore.match(this.options.sessionId, field.text, {
      fuzzyHammingMax: this.options.config.taint.fuzzyHammingMax,
      classes: ["sensitive"]
    }).map((match) => ({ field, match })));
    const taintedArgumentRoles = [...new Set(fieldMatches.map(({ field }) => field.role))];
    const temporal = matches.some((match) => match.reason === "temporal") || this.options.taintStore.hasTemporal(this.options.sessionId);
    const secretDetected = hasSecretLabel(argumentDetection.labels);
    const piiDetected = hasPiiLabel(argumentDetection.labels);
    const sensitiveTaint = sensitiveMatches.length > 0 || sensitiveFieldMatches.length > 0;
    const destination = summarizeDestinations(argumentFields, this.options.config.egress.allowlist);
    const allTaintMatches = [
      ...matches,
      ...fieldMatches.map(({ match }) => match),
      ...sensitiveMatches,
      ...sensitiveFieldMatches.map(({ match }) => match)
    ];

    const decision = evaluatePolicy(this.options.policy, {
      direction: "request",
      method: message.method,
      server: this.options.serverName,
      tool,
      tool_class: toolClass,
      capabilities: classification.capabilities,
      trust: this.options.server.trust,
      taint: matches.length > 0 || fieldMatches.length > 0,
      sensitive_taint: sensitiveTaint,
      temporal_taint: temporal,
      secret_detected: secretDetected,
      pii_detected: piiDetected,
      destination_allowed: destination.allowed,
      destination_allowlist_configured: destination.allowlistConfigured,
      detector_score: argumentDetection.score,
      labels: argumentDetection.labels,
      argument_text: argumentText,
      argument_roles: argumentRolesSummary(argumentFields),
      tainted_argument_roles: taintedArgumentRoles
    });

    const approval = await this.maybeApprove(decision, {
      method: message.method,
      tool,
      toolClass,
      classification,
      taintMatches: allTaintMatches,
      summary: `${tool} (${toolClass}; ${classification.capabilities.join(",") || "no capabilities"}) wants to run with ${matches.length + fieldMatches.length} taint match(es).`
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
      destination,
      sensitiveTaint,
      secretDetected,
      piiDetected,
      taintClasses: classesFromMatches(allTaintMatches),
      redacted: decision.action === "redact_secrets"
    });

    this.options.taintStore.consumeTurn(this.options.sessionId);

    if (!approval.approved || decision.action === "block") {
      return {
        toClient: message.id === undefined ? [] : [
          makeToolErrorResultResponse(
            message.id,
            formatBlockedToolCallResultText(decision, tool, this.options.config.audit.errorVerbosity)
          )
        ],
        toServer: []
      };
    }

    if (decision.action === "redact_secrets") {
      const redactedArguments = applyTextTransforms(params.arguments, (text, block) => maskSensitiveText(text, argumentDetectionsByPath.get(pathKey(block))?.spans));
      this.recordPending(message, tool);
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
          makeErrorResponse(message.id, -32021, "Palizade blocked tools/list metadata", {
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

    if (decision.action === "redact_spans" || decision.action === "redact_secrets") {
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
          makeErrorResponse(message.id, -32023, "Palizade blocked server-initiated model access", {
            decision,
            detector: detection
          })
        ]
      };
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
      .filter((block) => block.text.trim().length >= 8)
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

  private registerTaintFromContents(sourceName: string, classification: ToolClassification, contents: ExtractedContent[], detection: DetectionResult): TaintRecord[] {
    const highRiskSource = this.options.server.trust === "untrusted" || classification.toolClass === "source" || classification.capabilities.includes("reads_untrusted_content");
    return contents
      .filter((content) => content.text && content.text.trim().length >= 8 && content.kind !== "binary")
      .flatMap((content) => {
        const untrusted = highRiskSource || detection.score >= this.options.config.taint.suspiciousScore;
        const sensitive = this.isSensitiveOrigin(sourceName, content) || hasSecretLabel(detection.labels) || hasPiiLabel(detection.labels);
        const classes = taintClasses({ untrusted, sensitive });
        if (classes.length === 0) {
          return [];
        }
        return [this.options.taintStore.add({
          sessionId: this.options.sessionId,
          sourceServer: this.options.serverName,
          sourceTool: content.sourceToolOrResource ?? sourceName,
          trust: this.options.server.trust,
          text: content.text ?? "",
          detectorScore: detection.score,
          labels: detection.labels,
          classes
        })];
      });
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
        toClient: [makeErrorResponse(message.id, -32025, `Palizade blocked ${bucket} metadata`, { decision, detector: fused, lockChecks })],
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
    if (decision.action === "redact_spans" || decision.action === "redact_secrets") {
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
        toClient: [makeErrorResponse(message.id, -32027, "Palizade blocked initialize metadata", { decision, detector: fused, capabilityCheck })],
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
      argumentRoles?: string[];
      taintedArgumentRoles?: string[];
      taintClasses?: TaintClass[];
      destination?: DestinationSummary;
      sensitiveTaint?: boolean;
      secretDetected?: boolean;
      piiDetected?: boolean;
      redacted?: boolean;
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
      payload: scrubAuditPayload(extra.payload),
      metadata: {
        toolClass: extra.toolClass,
        capabilities: extra.classification?.capabilities,
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
        redacted: extra.redacted
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
    return this.options.server.sensitivePathPatterns.some((pattern) => {
      try {
        const regex = new RegExp(pattern, "iu");
        return searchable.some((value) => regex.test(value));
      } catch {
        return false;
      }
    });
  }
}

function pathKey(block: TextBlock): string {
  return block.path.join(".");
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

function classesFromMatches(matches: Array<TaintMatch | { taintId: string; reason: string; classes?: TaintClass[] | undefined }>): TaintClass[] {
  return dedupePreservingOrder(matches.flatMap((match) => match.classes ?? []));
}

function summarizeDestinations(argumentFields: ArgumentField[], allowlist: PalizadeConfig["egress"]["allowlist"]): DestinationSummary {
  const hosts = dedupePreservingOrder(argumentFields.flatMap((field) => hostsFromField(field)));
  const emails = dedupePreservingOrder(argumentFields
    .filter((field) => field.role === "email_recipient")
    .map((field) => field.text.toLowerCase()));
  const allowlistConfigured = allowlist.hosts.length > 0 || allowlist.emails.length > 0;
  const hostsAllowed = hosts.every((host) => allowlist.hosts.some((entry) => matchesHost(entry, host)));
  const emailsAllowed = emails.every((email) => allowlist.emails.some((entry) => matchesEmail(entry, email)));
  const hasDestinations = hosts.length > 0 || emails.length > 0;
  return {
    allowed: !allowlistConfigured || !hasDestinations || (hostsAllowed && emailsAllowed),
    allowlistConfigured,
    hosts,
    emailRecipients: emails.map(maskSensitiveValueForMetadata),
    destinationCount: hosts.length + emails.length
  };
}

function hostsFromField(field: ArgumentField): string[] {
  if (field.role === "hostname") {
    return [normalizeHost(field.text)].filter(Boolean);
  }
  if (field.role !== "url") {
    return [];
  }
  try {
    return [normalizeHost(new URL(field.text).hostname)].filter(Boolean);
  } catch {
    return [];
  }
}

function matchesHost(pattern: string, host: string): boolean {
  const normalizedPattern = normalizeHost(pattern);
  const normalizedHost = normalizeHost(host);
  if (!normalizedPattern || !normalizedHost) {
    return false;
  }
  if (normalizedPattern === "*") {
    return true;
  }
  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1);
    return normalizedHost.endsWith(suffix);
  }
  return normalizedPattern === normalizedHost;
}

function matchesEmail(pattern: string, email: string): boolean {
  const normalizedPattern = pattern.trim().toLowerCase();
  const normalizedEmail = email.trim().toLowerCase();
  if (!normalizedPattern || !normalizedEmail) {
    return false;
  }
  if (normalizedPattern === "*") {
    return true;
  }
  if (normalizedPattern.startsWith("*@")) {
    return normalizedEmail.endsWith(normalizedPattern.slice(1));
  }
  if (normalizedPattern.startsWith("@")) {
    return normalizedEmail.endsWith(normalizedPattern);
  }
  return normalizedPattern === normalizedEmail;
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/u, "");
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

function scrubClientBlockText(text: string): string {
  return text.replace(/\btaint_[A-Za-z0-9-]+\b/gu, "[taint-id]");
}

function trimTrailingPeriod(text: string): string {
  return text.endsWith(".") ? text.slice(0, -1) : text;
}

function dedupePreservingOrder<T extends string>(values: T[]): T[] {
  return [...new Set(values)];
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
