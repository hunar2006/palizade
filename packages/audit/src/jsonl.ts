import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pruneAnchors } from "./logger.js";
import { auditEventSchema, type AuditEvent, type AuditQuery, type AuditSink } from "./types.js";

export interface VerifyInput {
  /** Raw records in write order, exactly as stored. */
  records: Array<Record<string, unknown>>;
  /** Where each record is: a line number (JSONL) or row id (SQLite). */
  positions: number[];
  /** Records that could not be read at all. */
  unreadable: Array<{ position: number; reason: string }>;
  anchors: string[];
}

export class JsonlAuditSink implements AuditSink {
  constructor(private readonly path: string) {}

  async write(event: AuditEvent): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const parsed = auditEventSchema.parse(event);
    await appendFile(this.path, `${JSON.stringify(parsed)}\n`, "utf8");
  }

  async query(query: AuditQuery): Promise<AuditEvent[]> {
    let raw = "";
    try {
      raw = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return [];
      }
      throw error;
    }
    const events = raw
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((line) => auditEventSchema.parse(JSON.parse(line)))
      .filter((event) => matchesQuery(event, query));

    return events.slice(-(query.limit ?? 100));
  }

  /** The log as stored, for `audit verify`: not schema parsed, so added fields are not dropped. */
  async readForVerify(): Promise<VerifyInput> {
    const input: VerifyInput = { records: [], positions: [], unreadable: [], anchors: await readAnchors(`${this.path}.anchors`) };
    let raw: string;
    try { raw = await readFile(this.path, "utf8"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return input; throw error; }
    raw.split(/\r?\n/u).forEach((line, index) => {
      if (!line) return;
      try {
        const value: unknown = JSON.parse(line);
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not a JSON object");
        input.records.push(value as Record<string, unknown>);
        input.positions.push(index + 1);
      } catch (error) { input.unreadable.push({ position: index + 1, reason: `not a valid event: ${(error as Error).message}` }); }
    });
    return input;
  }

  async prune(before: Date): Promise<number> {
    const events = await this.query({ limit: Number.MAX_SAFE_INTEGER });
    const retained = events.filter((event) => new Date(event.ts) >= before);
    const anchors = [...new Set([...await readAnchors(`${this.path}.anchors`), ...pruneAnchors(events.filter((event) => new Date(event.ts) < before), retained)])];
    await mkdir(dirname(this.path), { recursive: true });
    if (anchors.length > 0) await writeFile(`${this.path}.anchors`, `${JSON.stringify(anchors)}\n`, "utf8");
    await writeFile(this.path, retained.map((event) => JSON.stringify(event)).join("\n") + (retained.length > 0 ? "\n" : ""), "utf8");
    return events.length - retained.length;
  }
}

export function matchesQuery(event: AuditEvent, query: AuditQuery): boolean {
  if (query.since && new Date(event.ts) < query.since) return false;
  if (query.action && event.action !== query.action) return false;
  if (query.session && event.session !== query.session) return false;
  if (query.server && event.server !== query.server) return false;
  if (query.tool && event.tool !== query.tool) return false;
  return true;
}

async function readAnchors(path: string): Promise<string[]> {
  try {
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}
