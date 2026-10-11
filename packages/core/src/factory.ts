import { LocalhostApprovalProvider, StaticApprovalProvider, TerminalApprovalProvider, type ApprovalProvider } from "@palizade/approvals";
import { AuditLogger, JsonlAuditSink, MetricsJsonlSink, SqliteAuditSink } from "@palizade/audit";
import { DetectorPipeline, HeuristicDetector, OptionalOnnxDetector, PromptGuard2Detector, SensitiveDataDetector, type Detector } from "@palizade/detectors";
import { SqliteTaintStore } from "@palizade/taint";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { loadPolicyFile } from "@palizade/policy";
import type { PalizadeConfig } from "./config.js";
import { HotReloader } from "./hot-reload.js";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";
import { SqliteToolRegistry } from "./metadata-guard.js";

export interface RuntimeComponents {
  engine: InterceptionEngine;
  audit: AuditLogger;
  detector: Detector;
  taintStore: SqliteTaintStore;
  lockfile: LockfileStore;
  approvals: ApprovalProvider;
  sessionId: string;
  reloader?: HotReloader | undefined;
}

export interface RuntimeOptions {
  /** palizade.yaml path; when set and `reload.enabled` is not false, policy, config and allowlist edits are hot reloaded. */
  configPath?: string | undefined;
}

export async function createRuntime(config: PalizadeConfig, serverName: string, options: RuntimeOptions = {}): Promise<RuntimeComponents> {
  const server = config.servers[serverName];
  if (!server) {
    throw new Error(`Server not found in palizade config: ${serverName}`);
  }

  const policy = await loadPolicyFile(config.policy);
  const audit = new AuditLogger([
    new JsonlAuditSink(config.audit.jsonl),
    new SqliteAuditSink(config.audit.sqlite),
    ...(config.metrics ? [new MetricsJsonlSink(config.metrics.jsonl, { maxBytes: config.metrics.maxBytes })] : [])
  ], {
    captureRawPayloads: config.audit.captureRawPayloads
  });
  const detector = createDetector(config);
  const taintStore = new SqliteTaintStore(config.taint.sqlite, {
    scope: config.taint.scope,
    profileId: config.taint.profileId,
    keyPath: config.taint.keyPath,
    ttlMs: config.taint.ttlMs,
    ...(process.env.PALIZADE_RUN_ID ? { runId: process.env.PALIZADE_RUN_ID } : {})
  });
  const lockfile = new LockfileStore(config.lockfile);
  const approvals = createApprovalProvider(config);
  const sessionId = `session_${randomUUID()}`;
  const toolRegistry = new SqliteToolRegistry(join(config.stateDir, "tool-registry.sqlite"));
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
    lockfile,
    toolRegistry
  });

  let reloader: HotReloader | undefined;
  if (options.configPath && config.reload?.enabled !== false) {
    reloader = new HotReloader({ configPath: options.configPath, serverName, sessionId, engine, audit, intervalMs: config.reload?.intervalMs });
    await reloader.start();
  }

  return { engine, audit, detector, taintStore, lockfile, approvals, sessionId, reloader };
}

export function createDetector(config: PalizadeConfig): Detector {
  const detectors: Detector[] = [];
  if (config.detectors.heuristic) {
    detectors.push(new HeuristicDetector());
  }
  if (config.detectors.secrets.enabled || config.detectors.pii.enabled) {
    detectors.push(new SensitiveDataDetector({
      secrets: config.detectors.secrets,
      pii: config.detectors.pii
    }));
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

function createApprovalProvider(config: PalizadeConfig): ApprovalProvider {
  if (config.approvals.mode === "static-allow") {
    return new StaticApprovalProvider(true, "configured static allow");
  }
  if (config.approvals.mode === "static-deny") {
    return new StaticApprovalProvider(false, "configured static deny");
  }
  if (config.approvals.mode === "localhost") {
    return new LocalhostApprovalProvider({
      defaultDecision: config.approvals.default,
      host: config.approvals.host,
      port: config.approvals.port,
      stateDir: config.stateDir,
      openBrowser: config.approvals.openBrowser
    });
  }
  return new TerminalApprovalProvider({ defaultDecision: config.approvals.default });
}
