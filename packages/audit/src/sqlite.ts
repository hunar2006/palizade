import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditQuery, AuditSink } from "./types.js";
import { auditEventSchema } from "./types.js";
import { matchesQuery, type VerifyInput } from "./jsonl.js";
import { pruneAnchors } from "./logger.js";

const COLUMNS = ["ts", "session", "server", "tool", "direction", "method", "action", "payload_hash"] as const;

type SqliteDatabase = {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...args: unknown[]): void;
    all(...args: unknown[]): unknown[];
    get(...args: unknown[]): unknown;
    iterate(): Iterable<unknown>;
  };
  close(): void;
};

export class SqliteAuditSink implements AuditSink {
  private db: SqliteDatabase | undefined;
  private initPromise: Promise<void> | undefined;

  constructor(private readonly path: string) {}

  async write(event: AuditEvent): Promise<void> {
    await this.ensureInit();
    if (!this.db) {
      throw new Error("SQLite audit sink is unavailable");
    }
    const parsed = auditEventSchema.parse(event);
    this.db.prepare(
      `insert into audit_events
       (ts, session, server, tool, direction, method, action, payload_hash, json)
       values (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      parsed.ts,
      parsed.session,
      parsed.server ?? null,
      parsed.tool ?? null,
      parsed.direction,
      parsed.method ?? null,
      parsed.action,
      parsed.payload_hash ?? null,
      JSON.stringify(parsed)
    );
  }

  async query(query: AuditQuery): Promise<AuditEvent[]> {
    const limit = query.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("Audit query limit must be a nonnegative integer");
    if (limit === 0) return [];
    await this.ensureInit();
    if (!this.db) {
      throw new Error("SQLite audit sink is unavailable");
    }
    const rows = this.db.prepare("select json from audit_events order by ts desc, id desc").iterate() as Iterable<{ json: string }>;
    const events: AuditEvent[] = [];
    for (const row of rows) {
      const event = auditEventSchema.parse(JSON.parse(row.json));
      if (!matchesQuery(event, query)) continue;
      events.push(event);
      if (events.length === limit) break;
    }
    return events.reverse();
  }

  close(): void {
    this.db?.close();
    this.db = undefined;
  }

  /** Rows in insert order, for `audit verify`. A row whose columns disagree with its JSON is unreadable. */
  async readForVerify(): Promise<VerifyInput> {
    await this.ensureInit();
    if (!this.db) throw new Error("SQLite audit sink is unavailable");
    const input: VerifyInput = { records: [], positions: [], unreadable: [], anchors: (this.db.prepare("select hash from audit_anchors").all() as Array<{ hash: string }>).map((row) => row.hash) };
    for (const row of this.db.prepare(`select id, ${COLUMNS.join(", ")}, json from audit_events order by id`).all() as Array<Record<string, unknown> & { id: number; json: string }>) {
      try {
        const value: unknown = JSON.parse(row.json);
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not a JSON object");
        const record = value as Record<string, unknown>;
        const changed = COLUMNS.filter((column) => (row[column] ?? null) !== (record[column] ?? null));
        if (changed.length > 0) throw new Error(`column ${changed.join(", ")} differs from the stored event`);
        input.records.push(record);
        input.positions.push(row.id);
      } catch (error) { input.unreadable.push({ position: row.id, reason: `not a valid event: ${(error as Error).message}` }); }
    }
    return input;
  }

  async prune(before: Date): Promise<number> {
    const cutoff = before.toISOString();
    await this.ensureInit();
    const db = this.db;
    if (!db) throw new Error("SQLite audit sink is unavailable");
    db.exec("begin immediate");
    try {
      const parse = (rows: unknown[]) => (rows as Array<{ json: string }>).map((row) => JSON.parse(row.json) as Record<string, unknown>);
      const removed = parse(db.prepare("select json from audit_events where ts < ?").all(cutoff));
      const kept = parse(db.prepare("select json from audit_events where ts >= ?").all(cutoff));
      const addAnchor = db.prepare("insert or ignore into audit_anchors (hash) values (?)");
      for (const hash of pruneAnchors(removed, kept)) addAnchor.run(hash);
      db.prepare("delete from audit_events where ts < ?").run(cutoff);
      db.exec("commit");
      return removed.length;
    } catch (error) {
      db.exec("rollback");
      throw error;
    }
  }

  private async ensureInit(): Promise<void> {
    this.initPromise ??= this.init();
    return this.initPromise;
  }

  private async init(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const sqlite = await import("node:sqlite");
    this.db = new sqlite.DatabaseSync(this.path);
    this.db.exec(`
        pragma busy_timeout = 5000;
        create table if not exists audit_events (
          id integer primary key autoincrement,
          ts text not null,
          session text not null,
          server text,
          tool text,
          direction text not null,
          method text,
          action text not null,
          payload_hash text,
          json text not null
        );
        create index if not exists idx_audit_ts on audit_events(ts);
        create index if not exists idx_audit_session on audit_events(session);
        create index if not exists idx_audit_action on audit_events(action);
        create table if not exists audit_anchors (hash text primary key);
    `);
  }
}
