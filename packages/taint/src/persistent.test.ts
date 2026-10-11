import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { SqliteTaintStore } from "./sqlite.js";

it("keeps promoted provenance after TTL and across runs until explicit persistent prune", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-persistent-"));
  const stores: SqliteTaintStore[] = [];
  try {
    const open = (runId: string, profileId = "default") => { const store = new SqliteTaintStore(join(dir, "taint.sqlite"), { keyPath: join(dir, "key"), scope: "external_run_id", runId, profileId, ttlMs: 1 }); stores.push(store); return store; };
    const source = open("source"), later = open("later"), other = open("other", "other-profile");
    const text = "An untrusted page saved as a durable memory observation.";
    const record = source.add({ sessionId: "s", sourceServer: "fetch", sourceTool: "fetch_url", trust: "untrusted", text, detectorScore: 0, labels: [] });
    source.promotePersistent(record.id);
    expect(source.get(record.id)?.expiresAt).toBeUndefined();
    expect(source.pruneExpired(new Date(Date.now() + 86400000))).toBe(0);
    expect(later.match("s2", text).some((match) => match.taintId === record.id)).toBe(true);
    expect(other.match("s3", text)).toHaveLength(0);
    expect(later.match("s2", "Fresh unrelated user prose.")).toHaveLength(0);
    expect(later.pruneExpired(new Date(), true)).toBe(1);
    expect(source.get(record.id)).toBeUndefined();
  } finally { stores.forEach((store) => store.close()); await rm(dir, { recursive: true, force: true }); }
});
