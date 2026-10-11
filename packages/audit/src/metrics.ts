import { appendFile, mkdir, rename, stat } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditSink } from "./types.js";

export interface MetricsLine {
  ts: string;
  server?: string | undefined;
  tool?: string | undefined;
  method?: string | undefined;
  direction: AuditEvent["direction"];
  action: string;
  rule?: string | undefined;
  latency_ms: number;
  taint_count: number;
  label_count: number;
  detector_score_bucket: number;
  /** Running totals for this process: `total` plus one counter per action. */
  counters: Record<string, number>;
}

export interface MetricsSinkOptions {
  /** Rotate to `<path>.1` once the file reaches this size. */
  maxBytes?: number | undefined;
  warn?: ((message: string) => void) | undefined;
}

/**
 * One JSON line per audit decision with identifiers and counters only: no payloads, reasons, labels or argument text.
 * Write failures are reported once on stderr and never fail the decision.
 */
export class MetricsJsonlSink implements AuditSink {
  private readonly counters: Record<string, number> = { total: 0 };
  private readonly maxBytes: number;
  private size: number | undefined;
  private warned = false;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly path: string, private readonly options: MetricsSinkOptions = {}) {
    this.maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
  }

  write(event: AuditEvent): Promise<void> {
    this.counters.total = (this.counters.total ?? 0) + 1;
    this.counters[event.action] = (this.counters[event.action] ?? 0) + 1;
    const line = `${JSON.stringify(metricsLine(event, { ...this.counters }))}\n`;
    this.queue = this.queue.then(() => this.append(line)).catch((error: unknown) => this.reportFailure(error));
    return this.queue;
  }

  private async append(line: string): Promise<void> {
    if (this.size === undefined) {
      await mkdir(dirname(this.path), { recursive: true });
      this.size = await stat(this.path).then((info) => info.size, () => 0);
    }
    const bytes = Buffer.byteLength(line);
    if (this.size + bytes > this.maxBytes && this.size > 0) {
      await rename(this.path, `${this.path}.1`);
      this.size = 0;
    }
    await appendFile(this.path, line, "utf8");
    this.size += bytes;
  }

  private reportFailure(error: unknown): void {
    this.size = undefined;
    if (this.warned) return;
    this.warned = true;
    (this.options.warn ?? ((message: string) => console.warn(message)))(`[palizade] metrics file ${this.path} could not be written; continuing without metrics: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function metricsLine(event: AuditEvent, counters: Record<string, number>): MetricsLine {
  return {
    ts: event.ts,
    server: event.server,
    tool: event.tool,
    method: event.method,
    direction: event.direction,
    action: event.action,
    rule: event.matched_rule?.id,
    latency_ms: event.latency_ms,
    taint_count: event.taint_ids.length,
    label_count: event.detector.labels.length,
    detector_score_bucket: Math.floor(event.detector.score * 10) / 10,
    counters
  };
}
