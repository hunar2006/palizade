import { createHash, randomUUID } from "node:crypto";
import type { AuditEvent, AuditQuery, AuditSink, AuditWriteEvent } from "./types.js";
import { auditEventSchema } from "./types.js";

export interface AuditLoggerOptions {
  captureRawPayloads?: boolean;
}

export class AuditLogger {
  private previousEventHash = ZERO_HASH;
  private writeQueue = Promise.resolve();

  constructor(
    private readonly sinks: AuditSink[],
    private readonly options: AuditLoggerOptions = {}
  ) {}

  async write(event: AuditWriteEvent): Promise<void> {
    const { payload, ...rest } = event;
    const payloadText = payload === undefined ? undefined : typeof payload === "string" ? payload : JSON.stringify(payload);
    const eventBase = auditEventSchema.parse({
      ...rest,
      event_id: event.event_id ?? `audit_${randomUUID()}`,
      ts: event.ts ?? new Date().toISOString(),
      payload_hash: rest.payload_hash ?? (payloadText === undefined ? undefined : sha256(payloadText)),
      raw_payload: this.options.captureRawPayloads ? payload : undefined,
      previous_event_hash: this.previousEventHash
    });
    // Hash what the sinks will persist, including JSON's conversions of nested metadata and payload values.
    const { event_hash: _eventHash, ...persisted } = JSON.parse(JSON.stringify(eventBase)) as AuditEvent;
    const eventHash = sha256(`${this.previousEventHash}${canonicalStringify(persisted)}`);
    const parsed = { ...persisted, event_hash: eventHash };
    this.previousEventHash = eventHash;

    const write = this.writeQueue.then(async () => {
      const results = await Promise.allSettled(this.sinks.map((sink) => sink.write(parsed)));
      const failed = results.find((result) => result.status === "rejected");
      if (failed) throw failed.reason;
    });
    this.writeQueue = write.catch(() => {});
    await write;
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
    await this.writeQueue;
    await Promise.all(this.sinks.map((sink) => sink.close?.()));
  }
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export interface ChainFailure {
  /** Position in the log: 0 based record index (the caller maps it to a line or row). */
  index: number;
  eventId?: string | undefined;
  reason: string;
}

/**
 * Checks the hash chains in a log, in the order the records were written. Each process starts its
 * own chain, and several processes can append to one log, so chains may interleave: every event
 * must extend the latest event of some chain (or start a new one), and each event can be extended
 * once. `anchors` are hashes of events removed by `audit prune` that kept events still point to.
 */
export function verifyAuditChain(events: ReadonlyArray<Record<string, unknown>>, anchors: Iterable<string> = []): { ok: boolean; legacyCount: number; segmentCount: number; failures: ChainFailure[] } {
  const present = new Set(events.map((event) => event.event_hash));
  const anchored = new Set([...anchors].filter((anchor) => !present.has(anchor)));
  const heads = new Set(anchored);
  const seen = new Set<string>();
  let legacyCount = 0;
  let segmentCount = 0;
  let chainStarted = false;
  const failures: ChainFailure[] = [];
  events.forEach((event, index) => {
    const eventId = typeof event.event_id === "string" ? event.event_id : undefined;
    const hash = event.event_hash, previous = event.previous_event_hash;
    if (!hash || !previous) {
      if (chainStarted) failures.push({ index, eventId, reason: "event without a hash after the hash chain started" });
      else legacyCount += 1;
      return;
    }
    chainStarted = true;
    if (typeof hash !== "string" || typeof previous !== "string") {
      failures.push({ index, eventId, reason: "hash fields are not strings" });
      return;
    }
    if (seen.has(hash)) failures.push({ index, eventId, reason: "duplicate of an earlier event" });
    if (previous === ZERO_HASH) segmentCount += 1;
    else if (heads.has(previous)) { heads.delete(previous); if (anchored.has(previous)) segmentCount += 1; }
    else failures.push({ index, eventId, reason: seen.has(previous) ? "out of order: its previous event was already followed by another" : "the event before it is missing or comes later (deleted or reordered)" });
    if (hash !== sha256(`${previous}${canonicalStringify({ ...event, event_hash: undefined })}`)) failures.push({ index, eventId, reason: "event was changed after it was written (hash mismatch)" });
    seen.add(hash);
    heads.add(hash);
  });
  return { ok: failures.length === 0, legacyCount, segmentCount, failures };
}

/** Keep predecessors of retained events and open chain ends that a live writer can still extend. */
export function pruneAnchors(removed: ReadonlyArray<Record<string, unknown>>, kept: ReadonlyArray<Record<string, unknown>>): string[] {
  const gone = new Set(removed.map((event) => event.event_hash).filter((hash): hash is string => typeof hash === "string"));
  const referencedByRemoved = new Set(removed.map((event) => event.previous_event_hash));
  const referencedByKept = new Set(kept.map((event) => event.previous_event_hash));
  return [...gone].filter((hash) => !referencedByRemoved.has(hash) || referencedByKept.has(hash));
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
