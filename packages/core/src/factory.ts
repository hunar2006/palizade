import { LocalhostApprovalProvider, StaticApprovalProvider, TerminalApprovalProvider, type ApprovalProvider } from "@palizade/approvals";
import { AuditLogger, JsonlAuditSink, MetricsJsonlSink, SqliteAuditSink } from "@palizade/audit";
import { DetectorPipeline, HeuristicDetector, OptionalOnnxDetector, PromptGuard2Detector, SensitiveDataDetector, type Detector } from "@palizade/detectors";
import { SqliteTaintStore } from "@palizade/taint";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { parsePolicy } from "@palizade/policy";
import { configSource, type PalizadeConfig } from "./config.js";
import { readSealSidecars, sealDrift, sealEnabled, sealPath } from "./canary.js";
import { LearnedEgress } from "./egress.js";
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
  close(): Promise<void>;
}

export interface RuntimeOptions {
  /** palizade.yaml path; when set and `reload.enabled` is not false, policy, config and allowlist edits are hot reloaded. */
  configPath?: string | undefined;
  /** Isolate listener session state without changing the configured provenance scope. */
  listenerSession?: boolean;
}

export async function createRuntime(config: PalizadeConfig, serverName: string, options: RuntimeOptions = {}): Promise<RuntimeComponents> {
  const server = config.servers[serverName];
  if (!server) {
    throw new Error(`Server not found in palizade config: ${serverName}`);
  }

  const source = configSource(config);
  const configPath = options.configPath ? resolve(options.configPath) : source?.path;
  const sealed = sealEnabled(config, configPath);
  const policyFile = await readFile(config.policy);
  const files = configPath ? [configPath, config.policy] : undefined;
  const sidecars = sealed ? readSealSidecars(config) : undefined;
  const loaded = sidecars && source && source.path === configPath
    ? { [source.path]: source.sha256, [config.policy]: createHash("sha256").update(policyFile).digest("hex"), ...sidecars.hashes }
    : undefined;
  const checkSeal = () => sealed
    ? sealDrift(config, files, loaded, true)
    : sealEnabled(config, configPath) ? [sealPath(config, configPath)] : [];
  if (sealed) {
    const drift = files && loaded ? checkSeal() : [sealPath(config, configPath)];
    if (drift.length > 0) throw new Error(`Palizade seal verification failed (${drift.map((file) => basename(file)).join(", ")}). Run palizade seal after approving the changes.`);
  }
  const policy = parsePolicy(policyFile.toString("utf8"), config.policy);
  const audit = new AuditLogger([
    new JsonlAuditSink(config.audit.jsonl),
    new SqliteAuditSink(config.audit.sqlite),
    ...(config.metrics ? [new MetricsJsonlSink(config.metrics.jsonl, { maxBytes: config.metrics.maxBytes })] : [])
  ], {
    captureRawPayloads: config.audit.captureRawPayloads
  });
  const detector = createDetector(config);
  let taintStore: SqliteTaintStore | undefined;
  let toolRegistry: SqliteToolRegistry | undefined;
  let reloader: HotReloader | undefined;
  let closing: Promise<void> | undefined;
  const sessionId = `session_${randomUUID()}`;
  const close = () => closing ??= (async () => {
    await reloader?.close();
    const results = await Promise.allSettled([
      audit.close(),
      Promise.resolve().then(() => toolRegistry?.close()),
      Promise.resolve().then(() => {
        try { if (options.listenerSession) taintStore?.clearListenerSession(sessionId); }
        finally { taintStore?.close(); }
      })
    ]);
    const failed = results.find((result) => result.status === "rejected");
    if (failed) throw failed.reason;
  })();

  try {
    taintStore = new SqliteTaintStore(config.taint.sqlite, {
      scope: config.taint.scope,
      profileId: config.taint.profileId,
      keyPath: config.taint.keyPath,
      ttlMs: config.taint.ttlMs,
      ...(options.listenerSession ? { sessionScope: "listener" as const } : {}),
      ...(process.env.PALIZADE_RUN_ID ? { runId: process.env.PALIZADE_RUN_ID } : {})
    });
    const lockfile = new LockfileStore(config.lockfile, sidecars?.lockBytes);
    const sealedLearnedEgress = sidecars ? new LearnedEgress(config.egress.learnedFile, undefined, sidecars.learnedBytes) : undefined;
    const approvals = createApprovalProvider(config, configPath);
    toolRegistry = new SqliteToolRegistry(join(config.stateDir, "tool-registry.sqlite"));
    const engine = new InterceptionEngine({ config, serverName, server, sessionId, policy, detector, taintStore, audit, approvals, lockfile, toolRegistry, checkSeal, sealedLearnedEgress });
    if (!sealed && options.configPath && config.reload?.enabled !== false) {
      reloader = new HotReloader({ configPath: options.configPath, serverName, sessionId, engine, audit, intervalMs: config.reload?.intervalMs });
      await reloader.start();
    }
    return { engine, audit, detector, taintStore, lockfile, approvals, sessionId, reloader, close };
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
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

function createApprovalProvider(config: PalizadeConfig, configPath?: string): ApprovalProvider {
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
      ...(configPath ? { configPath } : {}),
      stateDir: config.stateDir,
      openBrowser: config.approvals.openBrowser
    });
  }
  return new TerminalApprovalProvider({ defaultDecision: config.approvals.default });
}
