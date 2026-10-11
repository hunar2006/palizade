import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { diffToolsAgainstLock, formatToolDiff } from "./lock-diff.js";
import { LockfileStore } from "./lockfile.js";
import type { McpTool } from "./mcp.js";

const tag = (text: string): string => [...text].map((char) => String.fromCodePoint(0xe0000 + char.charCodeAt(0))).join("");

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function store(): Promise<LockfileStore> {
  const dir = await mkdtemp(join(tmpdir(), "palizade-lockdiff-"));
  dirs.push(dir);
  return new LockfileStore(join(dir, "palizade.lock"));
}

describe("lock diff", () => {
  it("shows hidden TAG characters as escaped code points", async () => {
    const lock = await store();
    await lock.approveTools("toy", [{ name: "lookup", description: "Look up a word." }]);
    const changed: McpTool[] = [{ name: "lookup", description: `Look up a word.${tag("A")}` }];
    const diff = diffToolsAgainstLock(await lock.read(), "toy", changed);
    const text = formatToolDiff("toy", diff);
    expect(diff[0]?.status).toBe("changed");
    expect(text).toContain("\\u{E0041}");
    expect(text).toContain("WARNING hidden characters: U+E0041");
    expect(text).toContain("first difference at byte 15");
    expect(text).not.toContain(tag("A"));
  });

  it("reports no changes for approved metadata", async () => {
    const lock = await store();
    const tools: McpTool[] = [{ name: "lookup", description: "Look up a word." }];
    await lock.approveTools("toy", tools);
    expect(formatToolDiff("toy", diffToolsAgainstLock(await lock.read(), "toy", tools))).toContain("matches the lockfile");
  });

  it("still diffs lock entries approved before snapshots existed", async () => {
    const lock = await store();
    await lock.write({ version: 1, servers: { toy: { tools: { lookup: { hash: "old", approvedAt: "2026-01-01T00:00:00Z" } } } } });
    const diff = diffToolsAgainstLock(await lock.read(), "toy", [{ name: "lookup", description: "Look up." }]);
    expect(diff[0]?.note).toContain("no stored snapshot");
    expect(diff[0]?.fields.some((field) => field.path === "description" && field.after === "Look up.")).toBe(true);
  });
});
