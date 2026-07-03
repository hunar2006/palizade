import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { auditEventSchema, type AuditEvent, type AuditQuery, type AuditSink } from "./types.js";

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

  async prune(before: Date): Promise<number> {
    const events = await this.query({ limit: Number.MAX_SAFE_INTEGER });
    const retained = events.filter((event) => new Date(event.ts) >= before);
    await mkdir(dirname(this.path), { recursive: true });
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
