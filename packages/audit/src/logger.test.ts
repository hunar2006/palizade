import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { AuditLogger, verifyAuditChain } from "./logger.js";
import { JsonlAuditSink } from "./jsonl.js";
import { SqliteAuditSink } from "./sqlite.js";
import type { AuditEvent } from "./types.js";

describe("AuditLogger", () => {
  it("writes hashed JSONL audit events without raw payloads by default", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const path = join(dir, "audit.jsonl");
    const logger = new AuditLogger([new JsonlAuditSink(path)]);

    await logger.write({
      session: "s1",
      server: "example",
      direction: "response",
      method: "tools/call",
      action: "sanitize",
      latency_ms: 4,
      payload: { secret: "do-not-log" }
    });

    const raw = await readFile(path, "utf8");
    const event = JSON.parse(raw);

    expect(event.payload_hash).toHaveLength(64);
    expect(event.raw_payload).toBeUndefined();

    await rm(dir, { recursive: true, force: true });
  });

  it("verifies hashed events while reporting legacy unhashed events", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const path = join(dir, "audit.jsonl");
    await writeFile(path, `${JSON.stringify({
      ts: new Date().toISOString(),
      session: "legacy",
      direction: "request",
      action: "allow",
      latency_ms: 0
    })}\n`, "utf8");
    const logger = new AuditLogger([new JsonlAuditSink(path)]);

    await logger.write({
      session: "s1",
      server: "example",
      direction: "request",
      method: "tools/call",
      action: "allow",
      latency_ms: 1
    });

    const events = await new JsonlAuditSink(path).query({ limit: 10 });
    const result = verifyAuditChain(events);

    expect(result.ok).toBe(true);
    expect(result.legacyCount).toBe(1);

    await rm(dir, { recursive: true, force: true });
  });

  it("verifies multiple hash-chain segments from separate logger processes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const path = join(dir, "audit.jsonl");
    const first = new AuditLogger([new JsonlAuditSink(path)]);
    const second = new AuditLogger([new JsonlAuditSink(path)]);

    await first.write({
      session: "s1",
      direction: "request",
      action: "allow",
      latency_ms: 1
    });
    await second.write({
      session: "s2",
      direction: "request",
      action: "block",
      latency_ms: 1
    });

    const events = await new JsonlAuditSink(path).query({ limit: 10 });
    const result = verifyAuditChain(events);

    expect(result.ok).toBe(true);
    expect(result.segmentCount).toBe(2);

    await rm(dir, { recursive: true, force: true });
  });

  it("persists overlapping writes in hash-chain order", async () => {
    const events: AuditEvent[] = [];
    const logger = new AuditLogger([{
      async write(event) {
        if (event.session === "first") await setImmediate();
        events.push(event);
      }
    }]);

    await Promise.all([
      logger.write({ session: "first", direction: "request", action: "allow" }),
      logger.write({ session: "second", direction: "request", action: "allow" })
    ]);

    expect(events.map((event) => event.session)).toEqual(["first", "second"]);
    expect(verifyAuditChain(events).ok).toBe(true);
  });

  it("hashes the persisted representation of captured data", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const sink = new JsonlAuditSink(join(dir, "audit.jsonl"));
    const logger = new AuditLogger([sink], { captureRawPayloads: true });
    try {
      const event = { session: "s1", direction: "request", action: "allow" } as const;
      const capturedAt = new Date("2026-10-01T00:00:00.000Z");
      await logger.write({ ...event, ts: undefined, event_id: undefined, metadata: { capturedAt }, payload: [undefined] });
      await logger.write({ ...event, payload: "" });

      const { records } = await sink.readForVerify();
      expect(records[0]).toMatchObject({ event_id: expect.any(String), metadata: { capturedAt: capturedAt.toISOString() }, raw_payload: [null] });
      expect(records[1]?.payload_hash).toHaveLength(64);
      expect(verifyAuditChain(records).ok).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([JsonlAuditSink, SqliteAuditSink])("limits matching results in %s", async (Sink) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const logger = new AuditLogger([new Sink(join(dir, "audit"))]);
    try {
      const event = { ts: "2026-10-01T00:00:00.000Z", direction: "request" } as const;
      await logger.write({ ...event, session: "older", action: "block" });
      await logger.write({ ...event, session: "matching", action: "block" });
      await logger.write({ ...event, session: "newest", action: "allow" });

      expect((await logger.query({ action: "block", limit: 1 })).map((record) => record.session)).toEqual(["matching"]);
      expect(await logger.query({ limit: 0 })).toEqual([]);
    } finally {
      await logger.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([JsonlAuditSink, SqliteAuditSink])("keeps an active chain verifiable when %s is pruned", async (Sink) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-audit-"));
    const path = join(dir, "audit");
    const pruner = new Sink(path);
    const logger = new AuditLogger([new Sink(path)]);
    const peer = new AuditLogger([new Sink(path)]);
    try {
      const event = { session: "active", direction: "request", action: "allow" } as const;
      await logger.write({ ...event, ts: "2026-10-01T00:00:00.000Z" });
      const [pruned] = await Promise.all([
        pruner.prune(new Date("2026-10-02T00:00:00.000Z")),
        peer.write({ ...event, session: "peer", ts: "2026-10-03T00:00:00.000Z" })
      ]);
      await logger.write({ ...event, ts: "2026-10-03T00:00:01.000Z" });

      expect(pruned).toBe(1);
      const { records, anchors } = await pruner.readForVerify();
      expect(records.map((record) => record.session)).toEqual(["peer", "active"]);
      expect(verifyAuditChain(records, anchors)).toMatchObject({ ok: true, segmentCount: 2 });
    } finally {
      await Promise.all([logger.close(), peer.close(), "close" in pruner ? pruner.close() : undefined]);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
