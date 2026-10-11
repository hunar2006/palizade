import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLogger } from "./logger.js";
import { MetricsJsonlSink } from "./metrics.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "palizade-metrics-"));
  dirs.push(dir);
  return dir;
}

describe("metrics jsonl", () => {
  it("writes counters for a blocked decision without payload, reason or labels", async () => {
    const dir = await tempDir();
    const path = join(dir, "metrics.jsonl");
    const audit = new AuditLogger([new MetricsJsonlSink(path)], { captureRawPayloads: true });
    await audit.write({ session: "s", server: "gh", tool: "create_issue", direction: "request", method: "tools/call", action: "allow", latency_ms: 2 });
    await audit.write({
      session: "s", server: "gh", tool: "create_issue", direction: "request", method: "tools/call", action: "block",
      matched_rule: { id: "block-tainted-sink" }, reason: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 leaked",
      detector: { score: 0.93, labels: ["github_token"] }, taint_ids: ["taint_1", "taint_2"], payload: { body: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" }
    });
    const raw = await readFile(path, "utf8");
    expect(raw).not.toContain("ghp_");
    expect(raw).not.toContain("github_token");
    const lines = raw.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ action: "allow", counters: { total: 1, allow: 1 } });
    expect(lines[1]).toEqual({
      ts: expect.any(String), server: "gh", tool: "create_issue", method: "tools/call", direction: "request", action: "block", rule: "block-tainted-sink",
      latency_ms: 0, taint_count: 2, label_count: 1, detector_score_bucket: 0.9, counters: { total: 2, allow: 1, block: 1 }
    });
  });

  it("rotates at maxBytes and never fails the decision when the file cannot be written", async () => {
    const dir = await tempDir();
    const path = join(dir, "metrics.jsonl");
    const sink = new MetricsJsonlSink(path, { maxBytes: 1024 });
    const audit = new AuditLogger([sink]);
    for (let index = 0; index < 20; index += 1) await audit.write({ session: "s", direction: "request", method: "tools/call", action: "allow" });
    expect((await stat(path)).size).toBeLessThanOrEqual(1024);
    expect((await stat(`${path}.1`)).size).toBeGreaterThan(0);

    const warnings: string[] = [];
    const broken = new AuditLogger([new MetricsJsonlSink(dir, { warn: (message) => warnings.push(message) })]);
    await expect(broken.write({ session: "s", direction: "request", action: "allow" })).resolves.toBeUndefined();
    await expect(broken.write({ session: "s", direction: "request", action: "allow" })).resolves.toBeUndefined();
    expect(warnings).toHaveLength(1);
  });
});
