import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditQuery, AuditSink } from "./types.js";
import { auditEventSchema } from "./types.js";

type SqliteDatabase = {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...args: unknown[]): void;
      all(...args: unknown[]): unknown[];
      get(...args: unknown[]): unknown;
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
    await this.ensureInit();
    if (!this.db) {
      throw new Error("SQLite audit sink is unavailable");
    }
    const rows = this.db.prepare("select json from audit_events order by ts desc limit ?").all(query.limit ?? 100) as Array<{ json: string }>;
    return rows
      .map((row) => auditEventSchema.parse(JSON.parse(row.json)))
      .filter((event) => {
        if (query.since && new Date(event.ts) < query.since) return false;
        if (query.action && event.action !== query.action) return false;
        if (query.session && event.session !== query.session) return false;
        if (query.server && event.server !== query.server) return false;
        if (query.tool && event.tool !== query.tool) return false;
        return true;
      })
      .reverse();
  }

  close(): void {
    this.db?.close();
    this.db = undefined;
  }

  async prune(before: Date): Promise<number> {
    await this.ensureInit();
    if (!this.db) {
      throw new Error("SQLite audit sink is unavailable");
    }
    const beforeCount = this.db.prepare("select count(*) as count from audit_events").get() as { count: number };
    this.db.prepare("delete from audit_events where ts < ?").run(before.toISOString());
    const afterCount = this.db.prepare("select count(*) as count from audit_events").get() as { count: number };
    return beforeCount.count - afterCount.count;
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
    `);
  }
}
