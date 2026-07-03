import { createHash, randomUUID } from "node:crypto";
import type { AuditEvent, AuditQuery, AuditSink, AuditWriteEvent } from "./types.js";
import { auditEventSchema } from "./types.js";

export interface AuditLoggerOptions {
  captureRawPayloads?: boolean;
}

export class AuditLogger {
  private previousEventHash = ZERO_HASH;

  constructor(
    private readonly sinks: AuditSink[],
    private readonly options: AuditLoggerOptions = {}
  ) {}

  async write(event: AuditWriteEvent): Promise<void> {
    const { payload, ...rest } = event;
    const payloadText = payload === undefined ? undefined : typeof payload === "string" ? payload : JSON.stringify(payload);
    const eventBase = auditEventSchema.parse({
      event_id: event.event_id ?? `audit_${randomUUID()}`,
      ts: event.ts ?? new Date().toISOString(),
      ...rest,
      payload_hash: rest.payload_hash ?? (payloadText ? sha256(payloadText) : undefined),
      raw_payload: this.options.captureRawPayloads ? payload : undefined,
      previous_event_hash: this.previousEventHash
    });
    const eventHash = sha256(`${this.previousEventHash}${canonicalStringify({ ...eventBase, event_hash: undefined })}`);
    const parsed = auditEventSchema.parse({ ...eventBase, event_hash: eventHash });
    this.previousEventHash = eventHash;

    await Promise.all(this.sinks.map((sink) => sink.write(parsed)));
  }

  async query(query: AuditQuery): Promise<AuditEvent[]> {
    for (const sink of this.sinks) {
      if (sink.query) {
        return sink.query(query);
      }
    }
    return [];
  }

  async close(): Promise<void> {
    await Promise.all(this.sinks.map((sink) => sink.close?.()));
  }
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function verifyAuditChain(events: AuditEvent[]): { ok: boolean; legacyCount: number; segmentCount: number; failures: Array<{ eventId?: string | undefined; reason: string }> } {
  let previous = ZERO_HASH;
  let legacyCount = 0;
  let segmentCount = 0;
  let chainStarted = false;
  const failures: Array<{ eventId?: string | undefined; reason: string }> = [];
  for (const event of events) {
    if (!event.event_hash || !event.previous_event_hash) {
      if (chainStarted) {
        failures.push({ eventId: event.event_id, reason: "legacy event after hash chain started" });
      } else {
        legacyCount += 1;
      }
      continue;
    }
    if (event.previous_event_hash === ZERO_HASH) {
      segmentCount += 1;
      previous = ZERO_HASH;
    }
    chainStarted = true;
    if (event.previous_event_hash !== previous) {
      failures.push({ eventId: event.event_id, reason: "previous hash mismatch" });
    }
    const expected = sha256(`${event.previous_event_hash}${canonicalStringify({ ...event, event_hash: undefined })}`);
    if (event.event_hash !== expected) {
      failures.push({ eventId: event.event_id, reason: "event hash mismatch" });
    }
    previous = event.event_hash;
  }
  return { ok: failures.length === 0, legacyCount, segmentCount, failures };
}

function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalStringify(record[key])}`)
    .join(",")}}`;
}

export function parseDuration(input: string): number {
  const match = /^(\d+)\s*(ms|s|m|h|d)$/iu.exec(input.trim());
  if (!match) {
    throw new Error(`Invalid duration: ${input}`);
  }
  const value = Number(match[1]);
  const unit = match[2]?.toLowerCase();
  switch (unit) {
    case "ms":
      return value;
    case "s":
      return value * 1_000;
    case "m":
      return value * 60_000;
    case "h":
      return value * 3_600_000;
    case "d":
      return value * 86_400_000;
    default:
      throw new Error(`Invalid duration unit: ${unit}`);
  }
}

const ZERO_HASH = "0".repeat(64);
