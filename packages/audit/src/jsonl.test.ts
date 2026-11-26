import { appendFile, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { JsonlAuditSink } from "./jsonl.js";
import { auditEventSchema } from "./types.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs/promises")>();
  return { ...fs, appendFile: vi.fn(fs.appendFile), unlink: vi.fn(fs.unlink) };
});

let dir: string;
let path: string;
let sink: JsonlAuditSink;
const event = auditEventSchema.parse({ ts: "2026-01-01T00:00:00Z", session: "test", direction: "internal", action: "log_only" });

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "palizade-audit-lock-"));
  path = join(dir, "audit.jsonl");
  sink = new JsonlAuditSink(path);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

it("records the writer PID and timestamp before writing", async () => {
  const start = Date.now();
  vi.mocked(appendFile).mockImplementationOnce(async () => {
    const owner = JSON.parse(await readFile(`${path}.lock`, "utf8"));
    expect(owner.pid).toBe(process.pid);
    expect(owner.timestamp).toBeGreaterThanOrEqual(start);
    expect(owner.timestamp).toBeLessThanOrEqual(Date.now());
  });
  await sink.write(event);
  await expect(readFile(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
});

it("recovers a fresh lock whose owner PID is dead", async () => {
  const deadPid = 123_456;
  vi.spyOn(process, "kill").mockImplementationOnce(() => { throw Object.assign(new Error("No such process"), { code: "ESRCH" }); });
  await writeFile(`${path}.lock`, JSON.stringify({ pid: deadPid, timestamp: Date.now() }));
  await sink.write(event);
  expect(process.kill).toHaveBeenCalledWith(deadPid, 0);
  expect(await sink.query({})).toEqual([event]);
});

it("recovers a lock over 30 seconds old even when the PID is live", async () => {
  await writeFile(`${path}.lock`, JSON.stringify({ pid: process.pid, timestamp: Date.now() - 31_000 }));
  await sink.write(event);
  expect(await sink.query({})).toEqual([event]);
});

it("warns on an EPERM after writing the audit event and resolves the write", async () => {
  vi.mocked(unlink).mockRejectedValueOnce(Object.assign(new Error("operation not permitted"), { code: "EPERM" }));
  const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
  await expect(sink.write(event)).resolves.toBeUndefined();
  expect(await sink.query({})).toEqual([event]);
  expect(warn).toHaveBeenCalledWith(expect.stringContaining("EPERM"));
});
