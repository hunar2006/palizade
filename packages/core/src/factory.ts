import { LocalhostApprovalProvider, StaticApprovalProvider, TerminalApprovalProvider, type ApprovalProvider } from "@palisade/approvals";
import { AuditLogger, JsonlAuditSink, SqliteAuditSink } from "@palisade/audit";
import { DetectorPipeline, HeuristicDetector, OptionalOnnxDetector, PromptGuard2Detector, type Detector } from "@palisade/detectors";
import { SqliteTaintStore } from "@palisade/taint";
import { randomUUID } from "node:crypto";
import { loadPolicyFile } from "@palisade/policy";
import type { PalisadeConfig } from "./config.js";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";

export interface RuntimeComponents {
  engine: InterceptionEngine;
  audit: AuditLogger;
  detector: Detector;
  taintStore: SqliteTaintStore;
  lockfile: LockfileStore;
  approvals: ApprovalProvider;
  sessionId: string;
}

export async function createRuntime(config: PalisadeConfig, serverName: string): Promise<RuntimeComponents> {
  const server = config.servers[serverName];
  if (!server) {
    throw new Error(`Server not found in palisade config: ${serverName}`);
  }

  const policy = await loadPolicyFile(config.policy);
  const audit = new AuditLogger([
    new JsonlAuditSink(config.audit.jsonl),
    new SqliteAuditSink(config.audit.sqlite)
  ], {
    captureRawPayloads: config.audit.captureRawPayloads
  });
  const detector = createDetector(config);
  const taintStore = new SqliteTaintStore(config.taint.sqlite, {
    scope: config.taint.scope,
    profileId: config.taint.profileId,
    keyPath: config.taint.keyPath,
    ttlMs: config.taint.ttlMs,
    ...(process.env.PALISADE_RUN_ID ? { runId: process.env.PALISADE_RUN_ID } : {})
  });
  const lockfile = new LockfileStore(config.lockfile);
  const approvals = createApprovalProvider(config);
  const sessionId = `session_${randomUUID()}`;
  const engine = new InterceptionEngine({
    config,
    serverName,
    server,
    sessionId,
    policy,
    detector,
    taintStore,
    audit,
    approvals,
    lockfile
  });

  return { engine, audit, detector, taintStore, lockfile, approvals, sessionId };
}

export function createDetector(config: PalisadeConfig): Detector {
  const detectors: Detector[] = [];
  if (config.detectors.heuristic) {
    detectors.push(new HeuristicDetector());
  }
  if (config.detectors.onnxModelPath) {
    detectors.push(new OptionalOnnxDetector({ modelPath: config.detectors.onnxModelPath }));
  }
  if (config.detectors.promptGuard2.enabled) {
    detectors.push(new PromptGuard2Detector({
      model: config.detectors.promptGuard2.model,
      ...(config.detectors.promptGuard2.cacheDir ? { cacheDir: config.detectors.promptGuard2.cacheDir } : {}),
      device: config.detectors.promptGuard2.device
    }));
  }
  return new DetectorPipeline(detectors);
}

function createApprovalProvider(config: PalisadeConfig): ApprovalProvider {
  if (config.approvals.mode === "static-allow") {
    return new StaticApprovalProvider(true, "configured static allow");
  }
  if (config.approvals.mode === "static-deny") {
    return new StaticApprovalProvider(false, "configured static deny");
  }
  if (config.approvals.mode === "localhost") {
    return new LocalhostApprovalProvider({ defaultDecision: config.approvals.default });
  }
  return new TerminalApprovalProvider({ defaultDecision: config.approvals.default });
}
