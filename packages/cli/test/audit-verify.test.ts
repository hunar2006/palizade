import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { AuditLogger, JsonlAuditSink, SqliteAuditSink } from "@palizade/audit";
import { afterEach, describe, expect, it } from "vitest";

const cli = resolve("packages/cli/dist/index.cjs");
const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

/** A project whose audit log holds two interleaved chains (two processes), in JSONL and SQLite. */
async function project() {
  const dir = await mkdtemp(join(tmpdir(), "palizade-verify-"));
  dirs.push(dir);
  await writeFile(join(dir, "palizade.yaml"), "servers: {}\n");
  const jsonl = join(dir, ".palizade", "audit.jsonl"), sqlite = join(dir, ".palizade", "audit.sqlite");
  const sinks = [new JsonlAuditSink(jsonl), new SqliteAuditSink(sqlite)];
  const first = new AuditLogger(sinks), second = new AuditLogger(sinks);
  for (let index = 0; index < 3; index += 1) {
    // About 3, 2 and 1 days old, so `audit prune --older-than 3d` removes the first of each chain.
    const ts = (offset: number) => new Date(Date.now() - (3 - index) * 86_400_000 + 3_600_000 * (index === 0 ? -1 : 0) + offset).toISOString();
    await first.write({ ts: ts(0), session: "a", direction: "request", action: "allow", latency_ms: index });
    await second.write({ ts: ts(1000), session: "b", direction: "request", action: "block", latency_ms: index });
  }
  (sinks[1] as SqliteAuditSink).close();
  const verify = (...flags: string[]) => {
    const run = spawnSync(process.execPath, [cli, "-c", join(dir, "palizade.yaml"), "audit", "verify", ...flags], { encoding: "utf8" });
    return { status: run.status, out: run.stdout + run.stderr };
  };
  const lines = async () => (await readFile(jsonl, "utf8")).trimEnd().split("\n");
  const setLines = (values: string[]) => writeFile(jsonl, `${values.join("\n")}\n`);
  const sql = async (statement: string) => {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(sqlite);
    try { db.exec(statement); } finally { db.close(); }
  };
  return { dir, verify, lines, setLines, sql };
}

describe("palizade audit verify", () => {
  it("accepts interleaved chains from two processes in both stores", async () => {
    const { verify } = await project();
    const result = verify();
    expect(result.status).toBe(0);
    expect(result.out).toMatch(/JSONL .*chain OK \(6 event\(s\) in 2 chain\(s\)\)/u);
    expect(result.out).toMatch(/SQLite .*chain OK \(6 event\(s\) in 2 chain\(s\)\)/u);
  });

  it("reports a changed JSONL event at its line, and an added field", async () => {
    const { verify, lines, setLines } = await project();
    const original = await lines();
    await setLines(original.map((line, index) => index === 3 ? line.replace('"action":"block"', '"action":"allow"') : line));
    let result = verify("--jsonl");
    expect(result.status).toBe(1);
    expect(result.out).toMatch(/chain BROKEN at line 4 \(event [^)]+\): event was changed after it was written/u);
    await setLines(original.map((line, index) => index === 2 ? line.replace(/\}$/u, ',"note":"added"}') : line));
    result = verify("--jsonl");
    expect(result.out).toMatch(/chain BROKEN at line 3 .*event was changed/u);
  });

  it("reports a deleted JSONL event at the event after it", async () => {
    const { verify, lines, setLines } = await project();
    const original = await lines();
    await setLines(original.filter((_line, index) => index !== 2)); // the second event of chain a
    const result = verify("--jsonl");
    expect(result.status).toBe(1);
    expect(result.out).toMatch(/chain BROKEN at line 4 .*the event before it is missing or comes later/u);
  });

  it("reports reordered and duplicated JSONL events", async () => {
    const { verify, lines, setLines } = await project();
    const original = await lines();
    const swapped = [...original];
    [swapped[0], swapped[2]] = [swapped[2]!, swapped[0]!]; // chain a's first two events
    await setLines(swapped);
    let result = verify("--jsonl");
    expect(result.status).toBe(1);
    expect(result.out).toMatch(/chain BROKEN at line 1 /u);
    await setLines([...original, original[4]!]);
    result = verify("--jsonl");
    expect(result.out).toMatch(/chain BROKEN at line 7 .*duplicate of an earlier event/u);
    await setLines([...original.slice(0, 2), "{not json", ...original.slice(2)]);
    expect(verify("--jsonl").out).toMatch(/chain BROKEN at line 3: not a valid event/u);
  });

  it("reports SQLite rows that were changed, deleted or reordered", async () => {
    let p = await project();
    await p.sql("update audit_events set action = 'allow' where id = 2");
    let result = p.verify("--sqlite");
    expect(result.status).toBe(1);
    expect(result.out).toMatch(/SQLite .*BROKEN at row 2: not a valid event: column action differs from the stored event/u);

    p = await project();
    await p.sql("update audit_events set json = replace(json, '\"action\":\"block\"', '\"action\":\"allow\"'), action = 'allow' where id = 4");
    expect(p.verify("--sqlite").out).toMatch(/BROKEN at row 4 .*event was changed/u);

    p = await project();
    await p.sql("delete from audit_events where id = 3");
    expect(p.verify("--sqlite").out).toMatch(/BROKEN at row 5 .*missing or comes later/u);

    p = await project();
    await p.sql("update audit_events set id = 100 where id = 1");
    result = p.verify("--sqlite");
    expect(result.status).toBe(1);
    expect(result.out).toMatch(/BROKEN at row 3 /u);
  });

  it("still verifies after audit prune removes the oldest events", async () => {
    const { dir, verify } = await project();
    const pruned = spawnSync(process.execPath, [cli, "-c", join(dir, "palizade.yaml"), "audit", "prune", "--older-than", "3d"], { encoding: "utf8" });
    expect(pruned.stdout).toContain("Pruned 2 audit event(s).");
    const result = verify();
    expect(result.status, result.out).toBe(0);
    expect(result.out).toMatch(/JSONL .*chain OK \(4 event\(s\) in 2 chain\(s\)\)/u);
  });
});
