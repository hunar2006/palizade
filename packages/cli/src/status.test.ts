import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteTaintStore } from "@palizade/taint";
import { afterEach, describe, expect, it } from "vitest";
import { buildStatus } from "./status.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "palizade-status-"));
  dirs.push(dir);
  await mkdir(join(dir, ".palizade"), { recursive: true });
  await writeFile(join(dir, "policy.yaml"), "version: 1\nrules: []\n");
  await writeFile(join(dir, "palizade.yaml"), [
    "policy: policy.yaml",
    "servers:",
    "  fs: { command: node, sandbox: docker }",
    "  remote: { url: 'https://example.test/mcp', protocolVersion: '2026-07-28' }",
    ""
  ].join("\n"));
  return dir;
}

describe("status", () => {
  it("reports quarantine, Rule of Two, taint kinds, lock state and the last 10 blocks", async () => {
    const dir = await project();
    await writeFile(join(dir, "palizade.lock"), JSON.stringify({ version: 1, servers: { fs: { tools: { read_file: { hash: "h", approvedAt: "2026-10-01T00:00:00.000Z" } } } } }));
    const store = new SqliteTaintStore(join(dir, ".palizade", "taint.sqlite"), { keyPath: join(dir, ".palizade", "taint.key") });
    store.add({ sessionId: "a", sourceServer: "fs", sourceTool: "read_file", trust: "untrusted", text: "untrusted page text for status", detectorScore: 0.1, labels: [] });
    const memory = store.add({ sessionId: "a", sourceServer: "fs", sourceTool: "read_file", trust: "untrusted", text: "remembered note for status", detectorScore: 0.1, labels: [] });
    store.promotePersistent(memory.id);
    store.updateSession("a", (state) => ({ ...state, seenUntrusted: true, seenSensitive: true, quarantine: { expiresAt: Date.now() + 60_000, remainingTurns: 7 } }));
    store.close();
    const lines = Array.from({ length: 12 }, (_, index) => JSON.stringify({
      ts: new Date(Date.UTC(2026, 9, 1, 0, index)).toISOString(), session: "a", server: "fs", tool: `send_${index}`, direction: "request", method: "tools/call", action: "block", matched_rule: { id: "block-tainted-sink" }, reason: "Tainted content", metadata: { era: "2025-11-25" }
    }));
    lines.push(JSON.stringify({ ts: "2026-10-01T01:00:00.000Z", session: "a", server: "fs", direction: "response", method: "tools/list", action: "allow" }));
    await writeFile(join(dir, ".palizade", "audit.jsonl"), `${lines.join("\n")}\n`);

    const report = await buildStatus(join(dir, "palizade.yaml"));
    expect(report.taintRecordsByKind).toEqual({ normal: 1, persistent: 1 });
    expect(report.taintRecords).toBe(2);
    expect(report.sessions.quarantined).toHaveLength(1);
    expect(report.sessions.quarantined[0]).toMatchObject({ quarantine: { remainingTurns: 7 }, ruleOfTwo: true });
    expect(report.sessions.ruleOfTwo).toHaveLength(1);
    expect(report.lastBlocks).toHaveLength(10);
    expect(report.lastBlocks[0]).toMatchObject({ tool: "send_11", rule: "block-tainted-sink" });
    expect(report.servers).toEqual([
      expect.objectContaining({ name: "fs", transport: "stdio", lastSeenEra: "2025-11-25", lock: { state: "locked", tools: 1, lastApprovedAt: "2026-10-01T00:00:00.000Z" }, sandbox: "docker" }),
      expect.objectContaining({ name: "remote", transport: "http", era: "2026-07-28", lock: { state: "unlocked", tools: 0, lastApprovedAt: undefined } })
    ]);
  });

  it("reports a clean project without sessions or blocks", async () => {
    const dir = await project();
    const report = await buildStatus(join(dir, "palizade.yaml"));
    expect(report).toMatchObject({ taintRecords: 0, taintRecordsByKind: { normal: 0, persistent: 0 }, sessions: { total: 0, quarantined: [], ruleOfTwo: [] }, lastBlocks: [] });
    expect(report.policyHash).toMatch(/^[0-9a-f]{16}$/u);
  });
});
