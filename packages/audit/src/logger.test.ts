import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLogger, verifyAuditChain } from "./logger.js";
import { JsonlAuditSink } from "./jsonl.js";

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
});
