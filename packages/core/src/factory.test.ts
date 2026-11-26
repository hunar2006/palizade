import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { createRuntime, type RuntimeComponents } from "./factory.js";

it("isolates listener activity while preserving configured profile provenance", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-listener-runtime-"));
  const runtimes: RuntimeComponents[] = [];
  try {
    const configPath = join(dir, "palizade.yaml");
    await writeFile(configPath, "policy: policy.yaml\nservers:\n  upstream: { url: 'https://example.test' }\n");
    await writeFile(join(dir, "policy.yaml"), "version: 1\ndefaults: { action: allow }\nrules: []\n");
    const config = await loadConfig(configPath);
    const a = await createRuntime(config, "upstream", { listenerSession: true });
    runtimes.push(a);
    const b = await createRuntime(config, "upstream", { listenerSession: true });
    runtimes.push(b);
    const text = "Read the latest weekly report at https://reports.example.test/latest";
    const record = a.taintStore.add({ sessionId: a.sessionId, sourceServer: "upstream", sourceTool: "read_report", trust: "untrusted", text, detectorScore: 0, labels: [] });
    a.taintStore.updateSession(a.sessionId, (state) => ({ ...state, seenUntrusted: true }));
    a.taintStore.markTemporal(a.sessionId, [record.id], { ...config.taint.temporal, enabled: true });
    a.taintStore.addUserStatements(a.sessionId, ["host:reports.example.test"], 60_000);
    expect(b.taintStore.getSession(b.sessionId).seenUntrusted).toBe(false);
    expect(a.taintStore.hasTemporal(a.sessionId)).toBe(true);
    expect(b.taintStore.hasTemporal(b.sessionId)).toBe(false);
    expect(b.taintStore.hasUserStatements(b.sessionId)).toBe(false);
    expect(b.taintStore.match(b.sessionId, text)).toEqual(expect.arrayContaining([expect.objectContaining({ taintId: record.id })]));
    await a.close();
    expect(b.taintStore.getSession(a.sessionId).seenUntrusted).toBe(false);
    expect(b.taintStore.hasTemporal(a.sessionId)).toBe(false);
    expect(b.taintStore.hasUserStatements(a.sessionId)).toBe(false);
  } finally {
    await Promise.all(runtimes.map((runtime) => runtime.close()));
    await rm(dir, { recursive: true, force: true });
  }
});
