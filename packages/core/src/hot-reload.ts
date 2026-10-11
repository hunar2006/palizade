import { createHash } from "node:crypto";
import { unwatchFile, watchFile, type Stats } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import type { AuditLogger } from "@palizade/audit";
import { parsePolicy, type PolicyDocument } from "@palizade/policy";
import { loadConfig, type PalizadeConfig } from "./config.js";
import type { InterceptionEngine } from "./interceptor.js";

const MAX_RELOAD_FILE_BYTES = 1024 * 1024;

export interface HotReloaderOptions {
  configPath: string;
  serverName: string;
  sessionId: string;
  engine: InterceptionEngine;
  audit: AuditLogger;
  intervalMs?: number | undefined;
  warn?: ((message: string) => void) | undefined;
}

export interface ReloadOutcome {
  changed: Array<"config" | "policy">;
  failed?: { kind: "config" | "policy"; file: string; error: string } | undefined;
  restartRequired: string[];
}

/**
 * Watches palizade.yaml, the policy and the learned allowlist. A changed file is validated first and swapped into
 * the engine only if valid; a bad file keeps the previous version, is audited, and is reported on stderr.
 */
export class HotReloader {
  private readonly configPath: string;
  private readonly warn: (message: string) => void;
  private configHash: string | undefined;
  private policyHash: string | undefined;
  private policyPath: string;
  private allowPath: string;
  private queue: Promise<unknown> = Promise.resolve();
  private stopped = false;
  private readonly watched = new Set<string>();

  constructor(private readonly options: HotReloaderOptions) {
    this.configPath = resolve(options.configPath);
    this.warn = options.warn ?? ((message) => console.warn(message));
    this.policyPath = options.engine.currentConfig.policy;
    this.allowPath = options.engine.currentConfig.egress.learnedFile;
  }

  async start(): Promise<void> {
    this.configHash = await hashFile(this.configPath);
    this.policyHash = await hashFile(this.policyPath);
    this.watch(this.configPath, () => this.trigger());
    this.watch(this.policyPath, () => this.trigger());
    this.watch(this.allowPath, () => this.checkAllowlist());
  }

  stop(): void {
    this.stopped = true;
    for (const path of this.watched) unwatchFile(path);
    this.watched.clear();
  }

  /** Re-reads the files now. Serialized, so overlapping changes apply in order. */
  reloadNow(): Promise<ReloadOutcome> {
    const next = this.queue.then(() => this.reload());
    this.queue = next.catch(() => undefined);
    return next;
  }

  private trigger(): void {
    if (!this.stopped) void this.reloadNow();
  }

  private checkAllowlist(): void {
    if (this.stopped) return;
    try { this.options.engine.validateLearnedEgress(); } catch { /* with reload enabled the engine reports and keeps the old file */ }
  }

  private watch(path: string, onChange: () => void): void {
    if (this.watched.has(path)) return;
    this.watched.add(path);
    // Polling is reliable on Windows and with editors that replace files on save; persistent: false never keeps the process alive.
    watchFile(path, { interval: this.options.intervalMs ?? 1000, persistent: false }, (current: Stats, previous: Stats) => {
      if (current.mtimeMs !== previous.mtimeMs || current.size !== previous.size) onChange();
    });
  }

  private async reload(): Promise<ReloadOutcome> {
    const engine = this.options.engine;
    const previousConfig = engine.currentConfig;
    let config: PalizadeConfig | undefined;
    const configHash = await hashFile(this.configPath);
    if (configHash !== this.configHash) {
      try {
        await assertSize(this.configPath);
        config = await loadConfig(this.configPath);
        if (!config.servers[this.options.serverName]) throw new Error(`Server '${this.options.serverName}' is no longer defined in palizade.yaml.`);
      } catch (error) {
        return this.fail("config", this.configPath, error, configHash);
      }
    }

    const policyPath = (config ?? previousConfig).policy;
    const policyHash = await hashFile(policyPath);
    let policy: PolicyDocument | undefined;
    if (policyPath !== this.policyPath || policyHash !== this.policyHash) {
      try {
        await assertSize(policyPath);
        policy = parsePolicy(await readFile(policyPath, "utf8"), policyPath);
      } catch (error) {
        // A config pointing at a bad policy is rejected as a whole, so the engine never runs a half-applied change.
        this.watch(policyPath, () => this.trigger());
        return this.fail("policy", policyPath, error, undefined, policyHash);
      }
    }

    if (!config && !policy) return { changed: [], restartRequired: [] };
    try {
      engine.reload({ config, policy });
    } catch (error) {
      return this.fail(config ? "config" : "policy", config ? this.configPath : policyPath, error, configHash);
    }
    this.configHash = configHash;
    this.policyHash = policyHash;
    if (policyPath !== this.policyPath) {
      unwatchFile(this.policyPath);
      this.watched.delete(this.policyPath);
      this.policyPath = policyPath;
      this.watch(policyPath, () => this.trigger());
    }
    if (config && config.egress.learnedFile !== this.allowPath) {
      unwatchFile(this.allowPath);
      this.watched.delete(this.allowPath);
      this.allowPath = config.egress.learnedFile;
      this.watch(this.allowPath, () => this.checkAllowlist());
    }

    const changed: ReloadOutcome["changed"] = [...(config ? ["config" as const] : []), ...(policy ? ["policy" as const] : [])];
    const restartRequired = config ? restartOnlyChanges(previousConfig, config, this.options.serverName) : [];
    if (restartRequired.length > 0) {
      this.warn(`[palizade] ${this.configPath} reloaded; these settings take effect after a restart: ${restartRequired.join(", ")}`);
    }
    await this.options.audit.write({
      session: this.options.sessionId,
      server: this.options.serverName,
      direction: "internal",
      method: "config/reload",
      action: "log_only",
      reason: `Reloaded ${changed.join(" and ")}${policy ? ` (policy ${policyPath} sha256:${policyHash?.slice(0, 16)})` : ""}.`,
      metadata: { reload: { ok: true, changed, policy: policyPath, policyHash, restartRequired } }
    });
    return { changed, restartRequired };
  }

  private async fail(kind: "config" | "policy", file: string, error: unknown, configHash?: string, policyHash?: string): Promise<ReloadOutcome> {
    const message = error instanceof Error ? error.message : String(error);
    // A rejected config is remembered so only a new edit retries it; after a policy failure the config is retried with the next change.
    if (configHash !== undefined) this.configHash = configHash;
    if (kind === "policy" && policyHash !== undefined && file === this.policyPath) this.policyHash = policyHash;
    this.warn(`[palizade] ${file} is invalid; keeping the previous ${kind}.\n${message}`);
    await this.options.audit.write({
      session: this.options.sessionId,
      server: this.options.serverName,
      direction: "internal",
      method: "config/reload",
      action: "log_only",
      reason: `Rejected invalid ${kind} ${file}; kept the previous version.`,
      metadata: { reload: { ok: false, kind, file, error: message.slice(0, 2000) } }
    }).catch(() => undefined);
    return { changed: [], failed: { kind, file, error: message }, restartRequired: [] };
  }
}

/** Settings that live outside the engine (stores, sinks, transports, the upstream process) and only change on restart. */
export function restartOnlyChanges(previous: PalizadeConfig, next: PalizadeConfig, serverName: string): string[] {
  const keys: Array<[string, (config: PalizadeConfig) => unknown]> = [
    ["stateDir", (config) => config.stateDir],
    ["audit", (config) => config.audit],
    ["detectors", (config) => config.detectors],
    ["transport", (config) => config.transport],
    ["http", (config) => config.http],
    ["listener", (config) => config.listener],
    ["approvals", (config) => config.approvals],
    ["taint.sqlite", (config) => [config.taint.sqlite, config.taint.keyPath, config.taint.scope, config.taint.profileId, config.taint.ttlMs]],
    ["reload", (config) => config.reload],
    ["metrics", (config) => config.metrics],
    [`servers.${serverName} launch`, (config) => {
      const server = config.servers[serverName];
      return server ? [server.command, server.args, server.cwd, server.env, server.url, server.headers, server.sandbox, server.protocolVersion] : undefined;
    }]
  ];
  return keys.filter(([, pick]) => JSON.stringify(pick(previous)) !== JSON.stringify(pick(next))).map(([name]) => name);
}

async function hashFile(path: string): Promise<string | undefined> {
  try {
    return createHash("sha256").update(await readFile(path)).digest("hex");
  } catch {
    return undefined;
  }
}

async function assertSize(path: string): Promise<void> {
  const info = await stat(path);
  if (info.size > MAX_RELOAD_FILE_BYTES) throw new Error(`${path} is larger than ${MAX_RELOAD_FILE_BYTES} bytes.`);
}
