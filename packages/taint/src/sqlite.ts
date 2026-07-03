import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { extractAtomicTokens, hammingDistanceHex, makeFingerprint, makeSubstrings, normalizeText, simhash } from "./fingerprint.js";
import { hmacSha256Hex, newTaintId, sha256 } from "./hash.js";
import type { AddTaintInput, TaintClass, TaintFingerprint, TaintMatch, TaintMatchOptions, TaintRecord, TaintScope, TaintStore, TemporalTaintConfig } from "./types.js";

type SqliteDatabase = {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...args: unknown[]): void;
    all(...args: unknown[]): unknown[];
    get(...args: unknown[]): unknown;
  };
  close(): void;
};

interface TaintRow {
  id: string;
  profile_id?: string;
  scope_id?: string;
  run_id?: string | null;
  session_id: string;
  source_server: string;
  source_tool: string;
  trust: "trusted" | "semi" | "untrusted";
  created_at: string;
  expires_at?: string | null;
  payload_hash: string;
  detector_score: number;
  labels_json: string;
  classes_json?: string | null;
  fingerprint_json: string;
}

interface TemporalRow {
  session_id: string;
  source_taint_ids_json: string;
  expires_at: number;
  remaining_turns: number;
}

export interface SqliteTaintStoreOptions {
  scope?: TaintScope;
  profileId?: string;
  runId?: string;
  keyPath?: string;
  ttlMs?: number;
}

export class SqliteTaintStore implements TaintStore {
  private readonly db: SqliteDatabase;
  private readonly scope: TaintScope;
  private readonly profileId: string;
  private readonly runId: string | undefined;
  private readonly ttlMs: number;
  private readonly hmacKey: Buffer;

  constructor(private readonly path: string, options: SqliteTaintStoreOptions = {}) {
    this.scope = options.scope ?? "profile";
    this.profileId = options.profileId ?? "default";
    this.runId = options.runId;
    this.ttlMs = options.ttlMs ?? 86_400_000;
    mkdirSync(dirname(path), { recursive: true });
    this.hmacKey = loadOrCreateHmacKey(options.keyPath ?? resolve(dirname(path), "taint.key"));
    const sqlite = requireNodeSqlite();
    this.db = new sqlite.DatabaseSync(path);
    this.db.exec(`
      create table if not exists taint_records (
        id text primary key,
        profile_id text,
        scope_id text,
        run_id text,
        session_id text not null,
        source_server text not null,
        source_tool text not null,
        trust text not null,
        created_at text not null,
        expires_at text,
        payload_hash text not null,
        detector_score real not null,
        labels_json text not null,
        classes_json text,
        fingerprint_json text not null
      );
      create index if not exists idx_taint_session on taint_records(session_id);
      create table if not exists temporal_taint (
        session_id text primary key,
        source_taint_ids_json text not null,
        expires_at integer not null,
        remaining_turns integer not null
      );
      create index if not exists idx_temporal_expires on temporal_taint(expires_at);
    `);
    this.ensureColumn("taint_records", "profile_id", "text");
    this.ensureColumn("taint_records", "scope_id", "text");
    this.ensureColumn("taint_records", "run_id", "text");
    this.ensureColumn("taint_records", "expires_at", "text");
    this.ensureColumn("taint_records", "classes_json", "text");
    this.db.exec(`
      create index if not exists idx_taint_scope on taint_records(scope_id);
      create index if not exists idx_taint_expires on taint_records(expires_at);
      create index if not exists idx_taint_created on taint_records(created_at);
    `);
  }

  add(input: AddTaintInput): TaintRecord {
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + this.ttlMs);
    const scopeId = this.scopeId(input.sessionId);
    const record: TaintRecord = {
      id: newTaintId(),
      profileId: this.profileId,
      scopeId,
      runId: this.runId,
      sessionId: input.sessionId,
      sourceServer: input.sourceServer,
      sourceTool: input.sourceTool,
      trust: input.trust,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      payloadHash: sha256(input.text),
      detectorScore: input.detectorScore,
      labels: [...input.labels],
      classes: normalizeClasses(input.classes),
      fingerprint: makeProtectedFingerprint(input.text, this.hmacKey)
    };
    this.db.prepare(
      `insert into taint_records
       (id, profile_id, scope_id, run_id, session_id, source_server, source_tool, trust, created_at, expires_at, payload_hash, detector_score, labels_json, classes_json, fingerprint_json)
       values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      record.id,
      record.profileId,
      record.scopeId,
      record.runId ?? null,
      record.sessionId,
      record.sourceServer,
      record.sourceTool,
      record.trust,
      record.createdAt,
      record.expiresAt,
      record.payloadHash,
      record.detectorScore,
      JSON.stringify(record.labels),
      JSON.stringify(record.classes),
      JSON.stringify(record.fingerprint)
    );
    return record;
  }

  get(id: string): TaintRecord | undefined {
    const row = this.db.prepare("select * from taint_records where id = ?").get(id) as TaintRow | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  all(): TaintRecord[] {
    return (this.db.prepare("select * from taint_records order by created_at asc").all() as TaintRow[]).map(rowToRecord);
  }

  match(sessionId: string, text: string, options: TaintMatchOptions = {}): TaintMatch[] {
    this.pruneExpired();
    const incoming = makeProtectedFingerprint(text, this.hmacKey);
    const minNormalizedLength = options.minNormalizedLength ?? 16;
    const fuzzyHammingMax = options.fuzzyHammingMax ?? 7;
    const records = this.recordsForScope(sessionId);
    const matches: TaintMatch[] = [];

    for (const record of records) {
      if (!matchesClassFilter(record.classes, options.classes)) {
        continue;
      }
      const incomingFragments = new Set(incoming.substrings);
      const substring = record.fingerprint.substrings.find((candidate) => candidate.length >= minNormalizedLength && incomingFragments.has(candidate));
      if (substring) {
        matches.push({ taintId: record.id, reason: "substring", token: substring, classes: record.classes });
        continue;
      }

      const token = record.fingerprint.tokens.find((candidate) => candidate.length >= 8 && incoming.tokens.includes(candidate));
      if (token) {
        matches.push({ taintId: record.id, reason: "token", token, classes: record.classes });
        continue;
      }

      if (record.fingerprint.normalized.length >= 32 && incoming.normalized.length >= 32) {
        const distance = hammingDistanceHex(record.fingerprint.simhash, incoming.simhash);
        if (distance <= fuzzyHammingMax) {
          matches.push({ taintId: record.id, reason: "fuzzy", classes: record.classes, score: 1 - distance / 64 });
        }
      }
    }

    for (const temporal of this.activeTemporalRows(sessionId)) {
      for (const taintId of JSON.parse(temporal.source_taint_ids_json) as string[]) {
        const record = this.get(taintId);
        const classes = record?.classes ?? ["untrusted"];
        if (matchesClassFilter(classes, options.classes)) {
          matches.push({ taintId, reason: "temporal", classes });
        }
      }
    }

    return dedupeMatches(matches);
  }

  markTemporal(sessionId: string, sourceTaintIds: string[], config: TemporalTaintConfig): void {
    if (!config.enabled || sourceTaintIds.length === 0) {
      return;
    }
    const ids = JSON.stringify([...new Set(sourceTaintIds)]);
    const expiresAt = Date.now() + config.ttlMs;
    for (const key of this.temporalKeys(sessionId)) {
      this.db.prepare(
        `insert into temporal_taint (session_id, source_taint_ids_json, expires_at, remaining_turns)
         values (?, ?, ?, ?)
         on conflict(session_id) do update set
           source_taint_ids_json = excluded.source_taint_ids_json,
           expires_at = excluded.expires_at,
           remaining_turns = excluded.remaining_turns`
      ).run(key, ids, expiresAt, config.turns);
    }
  }

  consumeTurn(sessionId: string): void {
    for (const row of this.activeTemporalRows(sessionId)) {
      const remaining = row.remaining_turns - 1;
      if (remaining <= 0 || row.expires_at <= Date.now()) {
        this.db.prepare("delete from temporal_taint where session_id = ?").run(row.session_id);
      } else {
        this.db.prepare("update temporal_taint set remaining_turns = ? where session_id = ?").run(remaining, row.session_id);
      }
    }
  }

  hasTemporal(sessionId: string): boolean {
    return this.activeTemporalRows(sessionId).length > 0;
  }

  close(): void {
    this.db.close();
  }

  pruneExpired(now = new Date()): number {
    const before = this.db.prepare("select count(*) as count from taint_records").get() as { count: number };
    this.db.prepare("delete from taint_records where expires_at is not null and expires_at <= ?").run(now.toISOString());
    this.db.prepare("delete from temporal_taint where expires_at <= ? or remaining_turns <= 0").run(Date.now());
    const after = this.db.prepare("select count(*) as count from taint_records").get() as { count: number };
    return before.count - after.count;
  }

  private recordsForScope(sessionId: string): TaintRecord[] {
    const scopeId = this.scopeId(sessionId);
    return (this.db.prepare("select * from taint_records where scope_id = ? order by created_at asc").all(scopeId) as TaintRow[]).map(rowToRecord);
  }

  private activeTemporalRows(sessionId: string): TemporalRow[] {
    const keys = this.temporalKeys(sessionId);
    const rows: TemporalRow[] = [];
    for (const key of keys) {
      const row = this.db.prepare("select * from temporal_taint where session_id = ?").get(key) as TemporalRow | undefined;
      if (!row) {
        continue;
      }
      if (row.expires_at <= Date.now() || row.remaining_turns <= 0) {
        this.db.prepare("delete from temporal_taint where session_id = ?").run(key);
        continue;
      }
      rows.push(row);
    }
    return rows;
  }

  private temporalKeys(sessionId: string): string[] {
    return [this.scopeId(sessionId)];
  }

  private scopeId(sessionId: string): string {
    if (this.scope === "process") {
      return `process:${sessionId}`;
    }
    if (this.scope === "external_run_id") {
      return `run:${this.runId ?? sessionId}`;
    }
    return `profile:${this.profileId}`;
  }

  private ensureColumn(table: string, column: string, type: string): void {
    try {
      this.db.prepare(`alter table ${table} add column ${column} ${type}`).run();
    } catch {
      // Column already exists on fresh schemas.
    }
  }
}

function rowToRecord(row: TaintRow): TaintRecord {
  return {
    id: row.id,
    profileId: row.profile_id,
    scopeId: row.scope_id,
    runId: row.run_id ?? undefined,
    sessionId: row.session_id,
    sourceServer: row.source_server,
    sourceTool: row.source_tool,
    trust: row.trust,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? undefined,
    payloadHash: row.payload_hash,
    detectorScore: row.detector_score,
    labels: JSON.parse(row.labels_json) as string[],
    classes: row.classes_json ? JSON.parse(row.classes_json) as TaintClass[] : ["untrusted"],
    fingerprint: JSON.parse(row.fingerprint_json) as TaintFingerprint
  };
}

function normalizeClasses(classes: TaintClass[] | undefined): TaintClass[] {
  const normalized: TaintClass[] = classes && classes.length > 0 ? classes : ["untrusted"];
  return [...new Set<TaintClass>(normalized)];
}

function matchesClassFilter(classes: TaintClass[], filter: TaintClass[] | undefined): boolean {
  return !filter || filter.some((taintClass) => classes.includes(taintClass));
}

function makeProtectedFingerprint(input: string, key: Buffer): TaintFingerprint {
  const normalized = normalizeText(input);
  const fragments = makeSubstrings(normalized).map((fragment) => hmacSha256Hex(key, fragment));
  const tokens = extractAtomicTokens(input).map((token) => hmacSha256Hex(key, canonicalizeToken(token)));
  return {
    normalized: hmacSha256Hex(key, normalized),
    substrings: fragments,
    tokens,
    simhash: simhash(normalized)
  };
}

function canonicalizeToken(token: string): string {
  try {
    const url = new URL(token);
    url.hostname = url.hostname.toLowerCase();
    return url.toString();
  } catch {
    return normalizeText(token);
  }
}

function loadOrCreateHmacKey(path: string): Buffer {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) {
    return Buffer.from(readFileSync(path, "utf8").trim(), "hex");
  }
  const key = randomBytes(32);
  writeFileSync(path, key.toString("hex"), { encoding: "utf8", mode: 0o600 });
  return key;
}

function dedupeMatches(matches: TaintMatch[]): TaintMatch[] {
  const seen = new Set<string>();
  const deduped: TaintMatch[] = [];
  for (const match of matches) {
    const key = `${match.taintId}:${match.reason}:${match.token ?? ""}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(match);
    }
  }
  return deduped;
}

function requireNodeSqlite(): { DatabaseSync: new (path: string) => SqliteDatabase } {
  const load = createRequire(resolve(process.cwd(), ".palizade", "taint-sqlite.cjs"));
  return load("node:sqlite") as { DatabaseSync: new (path: string) => SqliteDatabase };
}
