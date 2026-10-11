import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { SqliteTaintStore } from "@palizade/taint";
import { expect, it } from "vitest";

it("clears shared quarantine through the CLI without clearing exposure flags", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-clear-"));
  const store = new SqliteTaintStore(join(dir, ".palizade", "taint.sqlite"), { keyPath: join(dir, ".palizade", "taint.key"), runId: "cli-test" });
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
