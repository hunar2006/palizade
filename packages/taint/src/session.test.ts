import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { SqliteTaintStore } from "./sqlite.js";

it("persists session flags across wrappers while isolating external runs", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-session-"));
  const stores: SqliteTaintStore[] = [];
  try {
    const open = (runId: string) => { const store = new SqliteTaintStore(join(dir, "taint.sqlite"), { keyPath: join(dir, "key"), scope: "profile", runId }); stores.push(store); return store; };
    const source = open("a"), sink = open("a"), other = open("b");
    source.updateSession("source", (state) => ({ ...state, seenSensitive: true }));
    sink.updateSession("sink", (state) => ({ ...state, seenUntrusted: true, trustedDestinations: [sink.destinationKey("email:user@example.test")] }));
    expect(source.getSession("source")).toMatchObject({ seenSensitive: true, seenUntrusted: true });
    expect(other.getSession("other")).toMatchObject({ seenSensitive: false, seenUntrusted: false });
    expect(JSON.stringify(source.getSession("source"))).not.toContain("user@example.test");
  } finally { stores.forEach((store) => store.close()); await rm(dir, { recursive: true, force: true }); }
});
