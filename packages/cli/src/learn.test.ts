import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AuditEvent } from "@palizade/audit";
import YAML from "yaml";
import { afterEach, describe, expect, it } from "vitest";
import { addToolClasses, formatLearnDraft, learnFromAudit, proposedToolClasses } from "./learn.js";

const since = new Date("2026-10-01T00:00:00.000Z");

function call(tool: string, action: string, metadata: Record<string, unknown>, taint_ids: string[] = []): AuditEvent {
  return { ts: "2026-10-05T00:00:00.000Z", session: "s", server: "github", tool, direction: "request", method: "tools/call", action, taint_ids, detector: { score: 0, labels: [] }, latency_ms: 0, metadata };
}

const events: AuditEvent[] = [
  call("create_issue", "allow", { toolClass: "sink", destination: { allowed: false, hosts: ["api.github.com"], emailRecipients: [] } }),
  call("create_issue", "allow", { toolClass: "sink", destination: { allowed: false, hosts: ["api.github.com"], emailRecipients: [] } }),
  call("send_mail", "require_approval", { toolClass: "sink", approved: true, destination: { allowed: false, hosts: [], emailRecipients: ["team@example.test"] } }),
  call("post", "block", { toolClass: "sink", destination: { allowed: false, hosts: ["evil.example"], emailRecipients: [] } }),
  call("post", "allow", { toolClass: "sink", destination: { allowed: false, hosts: ["paste.example"], emailRecipients: [] } }, ["taint_1"]),
  call("weird_tool", "allow", { toolClass: "unknown" }),
  call("search", "allow", { toolClass: "source", destination: { allowed: true, hosts: ["already.example"], emailRecipients: [] } }),
  { ...call("old", "allow", { toolClass: "sink" }), ts: "2026-09-01T00:00:00.000Z" }
];

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("learn", () => {
  it("drafts tool classes and allowlists, leaving out blocked and tainted destinations", () => {
    const draft = learnFromAudit(events, { since, existingToolClasses: { github: { search: "source" } } });
    const yaml = formatLearnDraft(draft, since);
    const parsed = YAML.parse(yaml) as { servers: Record<string, { toolClasses: Record<string, string> }>; egress: { allowlist: { hosts: string[]; emails: string[] } } };
    expect(parsed.servers.github!.toolClasses).toEqual({ create_issue: "sink", post: "sink", send_mail: "sink", weird_tool: "unknown" });
    expect(parsed.egress.allowlist).toEqual({ hosts: ["api.github.com"], emails: ["team@example.test"] });
    expect(yaml).toContain("#   evil.example: only seen in 1 blocked or denied call(s)");
    expect(yaml).toContain("#   paste.example: 1 call(s) carried tainted data");
    expect(yaml).toContain("weird_tool: unknown  # 1 call(s); classify as source, sink or pure");
    expect(yaml).not.toContain("already.example");
    expect(yaml).not.toContain("old:");
    expect(yaml.split("\n")[1]).toBe("# Review every entry before copying it into palizade.yaml. Palizade did not write any file.");
  });

  it("prints a draft from the CLI without writing any file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-learn-"));
    dirs.push(dir);
    await mkdir(join(dir, ".palizade"), { recursive: true });
    const configText = "servers:\n  github: { command: node }\n";
    await writeFile(join(dir, "palizade.yaml"), configText);
    await writeFile(join(dir, ".palizade", "audit.jsonl"), events.map((event) => JSON.stringify({ ...event, ts: new Date().toISOString() })).join("\n") + "\n");
    const before = [...await readdir(dir), ...await readdir(join(dir, ".palizade"))].sort();
    const output = execFileSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(dir, "palizade.yaml"), "learn", "--from-audit", "--since", "7d"], { encoding: "utf8" });
    expect(YAML.parse(output)).toMatchObject({ servers: { github: { toolClasses: { create_issue: "sink" } } } });
    expect([...await readdir(dir), ...await readdir(join(dir, ".palizade"))].sort()).toEqual(before);
    expect(await readFile(join(dir, "palizade.yaml"), "utf8")).toBe(configText);
  });

  it("proposes classes for unknown tools of one session and writes them only into palizade.yaml, keeping comments", () => {
    const other = { ...call("other_tool", "block", { toolClass: "unknown" }), session: "another" };
    const propose = (_server: string, tool: string) => tool === "weird_tool" ? { toolClass: "source", reasons: ["description:reads_untrusted_content"] } : undefined;
    const draft = learnFromAudit([...events, other], { since, session: "s", propose });
    expect(draft.servers.github!.toolClasses.other_tool).toBeUndefined();
    expect(formatLearnDraft(draft, since)).toContain("weird_tool: source  # 1 call(s); was unknown, proposed from description:reads_untrusted_content");
    // Only unknown tools with a proposal, on servers palizade.yaml configures.
    expect(proposedToolClasses(draft, ["github"])).toEqual([{ server: "github", tool: "weird_tool", toolClass: "source" }]);
    expect(proposedToolClasses(draft, [])).toEqual([]);
    const raw = "# my servers\nservers:\n  github: { command: node } # keep me\n  other:\n    command: x\n";
    const next = addToolClasses(raw, proposedToolClasses(draft, ["github"]));
    expect(next).toContain("# my servers");
    expect(next).toContain("# keep me");
    expect(YAML.parse(next).servers).toEqual({ github: { command: "node", toolClasses: { weird_tool: "source" } }, other: { command: "x" } });
    expect(() => addToolClasses(raw, [{ server: "missing", tool: "t", toolClass: "sink" }])).toThrow(/not in palizade.yaml/u);
  });

  it("refuses to write without a terminal to confirm", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-learn-write-"));
    dirs.push(dir);
    await mkdir(join(dir, ".palizade"), { recursive: true });
    const configText = "servers:\n  github: { command: node, trust: untrusted }\n";
    await writeFile(join(dir, "palizade.yaml"), configText);
    // A description is evidence only when a person vouches for the server, so this is proposed, not used.
    await writeFile(join(dir, "palizade.lock"), JSON.stringify({ version: 1, servers: { github: { tools: { weird_tool: { hash: "x", approvedAt: "2026-10-01T00:00:00.000Z", snapshot: { name: "weird_tool", description: "Read the latest report.", inputSchema: { type: "object" } } } } } } }));
    await writeFile(join(dir, ".palizade", "audit.jsonl"), events.map((event) => JSON.stringify({ ...event, ts: new Date().toISOString() })).join("\n") + "\n");
    const run = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(dir, "palizade.yaml"), "learn", "--session", "s", "--write"], { encoding: "utf8", input: "y\n" });
    expect(run.stdout).toContain("weird_tool: source  # 1 call(s); was unknown, proposed from");
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("needs a terminal");
    expect(await readFile(join(dir, "palizade.yaml"), "utf8")).toBe(configText);
  });
});
