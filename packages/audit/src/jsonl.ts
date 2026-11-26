import { randomUUID } from "node:crypto";
import { lstatSync, unlinkSync, type BigIntStats } from "node:fs";
import { appendFile, mkdir, open, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout } from "node:timers/promises";
import { pruneAnchors } from "./logger.js";
import { auditEventSchema, type AuditEvent, type AuditQuery, type AuditSink } from "./types.js";

const LOCK_STALE_MS = 30_000;

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
    const parsed = auditEventSchema.parse(event);
    await this.withWriteLock(() => appendFile(this.path, `${JSON.stringify(parsed)}\n`, "utf8"));
  }

  async query(query: AuditQuery): Promise<AuditEvent[]> {
    const limit = query.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("Audit query limit must be a nonnegative integer");
    if (limit === 0) return [];
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

    return events.slice(-limit);
  }

  /** The log as stored, for `audit verify`: not schema parsed, so added fields are not dropped. */
  async readForVerify(): Promise<VerifyInput> {
    const raw = await readFile(this.path, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return "";
    });
    // Prune publishes anchors before replacing the log, so an older log can use newer anchors.
    const input: VerifyInput = { records: [], positions: [], unreadable: [], anchors: await readAnchors(`${this.path}.anchors`) };
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
    if (!Number.isFinite(before.getTime())) throw new Error("Invalid audit prune cutoff");
    return this.withWriteLock(async () => {
      const input = await this.readForVerify();
      const problem = input.unreadable[0];
      if (problem) throw new Error(`Cannot prune invalid audit line ${problem.position}: ${problem.reason}`);
      const retained: VerifyInput["records"] = [];
      const removed: VerifyInput["records"] = [];
      for (const event of input.records) {
        const timestamp = new Date(auditEventSchema.parse(event).ts);
        if (!Number.isFinite(timestamp.getTime())) throw new Error("Cannot prune an audit event with an invalid timestamp");
        (timestamp < before ? removed : retained).push(event);
      }
      if (removed.length === 0) return 0;
      const anchors = [...new Set([...input.anchors, ...pruneAnchors(removed, retained)])];
      if (anchors.length > 0) await atomicWrite(`${this.path}.anchors`, `${JSON.stringify(anchors)}\n`);
      await atomicWrite(this.path, retained.map((event) => `${JSON.stringify(event)}\n`).join(""));
      return removed.length;
    });
  }

  private async withWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    await mkdir(dirname(this.path), { recursive: true });
    const lockPath = `${this.path}.lock`;
    const deadline = Date.now() + 5_000;
    for (;;) {
      const lock = await open(lockPath, "wx", 0o600).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "EEXIST") throw error;
        return undefined;
      });
      if (!lock) {
        if (Date.now() >= deadline) throw new Error(`Audit log lock did not clear: ${lockPath}`);
        if (!await recoverStaleLock(lockPath)) await setTimeout(20);
        continue;
      }
      const timestamp = Date.now();
      try {
        await lock.writeFile(JSON.stringify({ pid: process.pid, timestamp }), "utf8");
        return await operation();
      } finally {
        try {
          if (Date.now() - timestamp > LOCK_STALE_MS) {
            const identity = await lock.stat({ bigint: true }).finally(() => lock.close());
            unlinkSameLock(lockPath, identity);
          } else {
            await lock.close();
            await unlink(lockPath);
          }
        } catch (error) {
          const { code } = error as NodeJS.ErrnoException;
          if (code !== "ENOENT") console.warn(`[palizade] could not release audit log lock (${code ?? "unknown error"}): ${lockPath}`);
        }
      }
    }
  }
}

async function recoverStaleLock(path: string): Promise<boolean> {
  try {
    const lock = await open(path, "r");
    let identity: BigIntStats;
    try {
      identity = await lock.stat({ bigint: true });
      if (!identity.isFile()) return false;
      if (Date.now() - Number(identity.mtimeMs) <= LOCK_STALE_MS) {
        const buffer = Buffer.alloc(128);
        const { bytesRead } = await lock.read(buffer, 0, buffer.length, 0);
        if (!isStaleOwner(buffer.toString("utf8", 0, bytesRead))) return false;
      }
    } finally {
      await lock.close();
    }
    return unlinkSameLock(path, identity);
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT") return true;
    if (code === "EPERM" || code === "EACCES" || code === "EBUSY") return false;
    throw error;
  }
}

function isStaleOwner(raw: string): boolean {
  let owner: { pid?: unknown; timestamp?: unknown } | null;
  try { owner = JSON.parse(raw); } catch { return false; }
  const { pid, timestamp } = owner ?? {};
  if (typeof timestamp === "number" && timestamp > 0 && Date.now() - timestamp > LOCK_STALE_MS) return true;
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0 || pid > 0x7fff_ffff) return false;
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

function unlinkSameLock(path: string, identity: BigIntStats): boolean {
  const current = lstatSync(path, { bigint: true });
  if (current.dev !== identity.dev || current.ino !== identity.ino || current.birthtimeNs !== identity.birthtimeNs || current.mtimeNs !== identity.mtimeNs) return false;
  unlinkSync(path);
  return true;
}

async function atomicWrite(path: string, data: string): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, data, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
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
