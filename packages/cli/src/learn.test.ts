import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AuditEvent } from "@palizade/audit";
import YAML from "yaml";
import { afterEach, describe, expect, it } from "vitest";
import { formatLearnDraft, learnFromAudit } from "./learn.js";

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
});
