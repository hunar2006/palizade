import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { emptySession, SqliteTaintStore } from "@palizade/taint";
import { expect, it } from "vitest";

it("clears shared quarantine through the CLI without clearing exposure flags", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-clear-"));
  const store = new SqliteTaintStore(join(dir, ".palizade", "taint.sqlite"), { keyPath: join(dir, ".palizade", "taint.key"), runId: "cli-test", sessionScope: "client" });
  try {
    const config = join(dir, "palizade.yaml");
    await writeFile(config, "servers: {}\n");
    store.updateSession("s", (state) => ({ ...state, seenUntrusted: true, seenSensitive: true, quarantine: { expiresAt: Date.now() + 60000, remainingTurns: 20 } }));
    const output = execFileSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", config, "session", "quarantine", "--clear", "--session", "s"], { encoding: "utf8", env: { ...process.env, PALIZADE_RUN_ID: "cli-test" } });
    expect(output).toContain("quarantine cleared");
    expect(store.getSession("s").quarantine).toBeUndefined();
    expect(store.getSession("s")).toMatchObject({ seenUntrusted: true, seenSensitive: true });
  } finally { store.close(); await rm(dir, { recursive: true, force: true }); }
});

it.each([true, false])("resets only the selected session and preserves profile taint (client=%s)", async (client) => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-reset-"));
  const store = new SqliteTaintStore(join(dir, ".palizade", "taint.sqlite"), { keyPath: join(dir, ".palizade", "taint.key"), runId: "reset-run", ...(client ? { sessionScope: "client" as const } : {}) });
  try {
    const config = join(dir, "palizade.yaml");
    await writeFile(config, "servers: {}\n");
    const armed = { ...emptySession(), seenUntrusted: true, seenSensitive: true, exposureExpiresAt: Date.now() + 10000, quarantine: { expiresAt: Date.now() + 60000, remainingTurns: 20 }, trustedDestinations: ["hmac-grant"], repeats: { hmac: 10 }, sinkCalls: [Date.now()], trackingOverflow: true };
    store.updateSession("selected", () => armed);
    if (client) store.updateSession("other", () => armed);
    const record = store.add({ sessionId: "selected", sourceServer: "web", sourceTool: "fetch", trust: "untrusted", text: "Stored untrusted source content remains protected.", detectorScore: 0, labels: [] });
    const output = execFileSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", config, "session", "reset", ...(client ? ["--session", "selected"] : [])], { encoding: "utf8", env: { ...process.env, PALIZADE_RUN_ID: "reset-run" } });
    expect(output).toContain("taint records preserved");
    expect(store.getSession("selected")).toEqual(emptySession());
    if (client) expect(store.getSession("other")).toEqual(armed);
    expect(store.get(record.id)).toBeDefined();
    expect(store.match("other", "Stored untrusted source content remains protected.")).not.toEqual([]);
  } finally { store.close(); await rm(dir, { recursive: true, force: true }); }
});
