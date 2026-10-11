import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticApprovalProvider } from "@palizade/approvals";
import { AuditLogger, type AuditEvent } from "@palizade/audit";
import { HeuristicDetector } from "@palizade/detectors";
import { loadPolicyFile } from "@palizade/policy";
import { InMemoryTaintStore } from "@palizade/taint";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { HotReloader } from "./hot-reload.js";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";

const ALLOW_POLICY = "version: 1\ndefaults: { action: allow, on_error: block }\nrules: []\n";
const BLOCK_SINK_POLICY = "version: 1\ndefaults: { action: allow, on_error: block }\nrules:\n  - id: block-send\n    when: { direction: request, method: tools/call, tool: send_email }\n    action: block\n";
const CONFIG = (extra = "") => `policy: policy.yaml\nlockfile: palizade.lock\nstateDir: .palizade\nreload: { intervalMs: 100 }\n${extra}servers:\n  toy:\n    command: node\n    toolClasses: { send_email: sink }\n`;

let cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of cleanup.splice(0)) await step();
});

async function setup(policy = ALLOW_POLICY, configExtra = "") {
  const dir = await mkdtemp(join(tmpdir(), "palizade-reload-"));
  const configPath = join(dir, "palizade.yaml");
  await writeFile(configPath, CONFIG(configExtra));
  await writeFile(join(dir, "policy.yaml"), policy);
  const config = await loadConfig(configPath);
  const events: AuditEvent[] = [];
  const audit = new AuditLogger([{ write: async (event) => { events.push(event); } }]);
  const engine = new InterceptionEngine({
    config,
    serverName: "toy",
    server: config.servers.toy!,
    sessionId: "s1",
    policy: await loadPolicyFile(config.policy),
    detector: new HeuristicDetector(),
    taintStore: new InMemoryTaintStore(),
    audit,
    approvals: new StaticApprovalProvider(false, "test"),
    lockfile: new LockfileStore(config.lockfile)
  });
  const warnings: string[] = [];
  const reloader = new HotReloader({ configPath, serverName: "toy", sessionId: "s1", engine, audit, intervalMs: 100, warn: (message) => warnings.push(message) });
  await reloader.start();
  cleanup.push(async () => { reloader.stop(); await rm(dir, { recursive: true, force: true }); });
  return { dir, configPath, engine, reloader, events, warnings };
}

async function sendEmail(engine: InterceptionEngine, id: string): Promise<"forwarded" | "blocked"> {
  const output = await engine.handleClientMessage({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "send_email", arguments: { to: "a@example.test", body: "hi" } } });
  return output.toServer.length === 1 ? "forwarded" : "blocked";
}

describe("hot reload", () => {
  it("swaps in a valid policy and enforces it on the next call", async () => {
    const { dir, engine, reloader, events } = await setup();
    expect(await sendEmail(engine, "1")).toBe("forwarded");
    await writeFile(join(dir, "policy.yaml"), BLOCK_SINK_POLICY);
    expect(await reloader.reloadNow()).toMatchObject({ changed: ["policy"] });
    expect(await sendEmail(engine, "2")).toBe("blocked");
    expect(events.find((event) => event.method === "config/reload")?.metadata?.reload).toMatchObject({ ok: true, changed: ["policy"] });
  });

  it("keeps the previous policy when the new file is invalid, audits it and warns", async () => {
    const { dir, engine, reloader, events, warnings } = await setup(BLOCK_SINK_POLICY);
    await writeFile(join(dir, "policy.yaml"), "version: 1\nrules:\n  - id: broken\n    action: alow\n");
    const outcome = await reloader.reloadNow();
    expect(outcome.failed).toMatchObject({ kind: "policy" });
    expect(engine.currentPolicy.rules.map((rule) => rule.id)).toEqual(["block-send"]);
    expect(await sendEmail(engine, "3")).toBe("blocked");
    expect(warnings.join("\n")).toMatch(/policy\.yaml is invalid; keeping the previous policy\.\n.*rules\.0\.action \(line 4\)/su);
    expect(events.find((event) => event.method === "config/reload")).toMatchObject({ action: "log_only", metadata: { reload: { ok: false, kind: "policy" } } });
  });

  it("keeps the previous config when palizade.yaml becomes invalid, then accepts a fix", async () => {
    const { configPath, engine, reloader, warnings } = await setup();
    const before = engine.currentConfig;
    await writeFile(configPath, `${CONFIG()}bogus: true\n`);
    expect((await reloader.reloadNow()).failed).toMatchObject({ kind: "config" });
    expect(engine.currentConfig).toBe(before);
    expect(warnings[0]).toMatch(/Unknown key 'bogus'/u);
    await writeFile(configPath, CONFIG("egress: { mode: allowlist_only }\n"));
    expect(await reloader.reloadNow()).toMatchObject({ changed: ["config"] });
    expect(engine.currentConfig.egress.mode).toBe("allowlist_only");
  });

  it("keeps the last valid learned allowlist instead of failing every sink call", async () => {
    const { dir, engine, events, warnings } = await setup();
    await writeFile(join(dir, "palizade.allow.yaml"), "hosts: [ok.example]\n");
    engine.validateLearnedEgress();
    await writeFile(join(dir, "palizade.allow.yaml"), "hosts: not-a-list\n");
    expect(() => engine.validateLearnedEgress()).not.toThrow();
    expect(await sendEmail(engine, "4")).toBe("forwarded");
    await new Promise((resolveTick) => setImmediate(resolveTick));
    expect(events.some((event) => event.method === "config/reload" && /allowlist/u.test(event.reason ?? ""))).toBe(true);
    expect(warnings).toEqual([]);
  });

  it("notices edits through the file watcher", async () => {
    const { dir, engine } = await setup();
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
    await writeFile(join(dir, "policy.yaml"), BLOCK_SINK_POLICY);
    const deadline = Date.now() + 5000;
    while (engine.currentPolicy.rules.length === 0 && Date.now() < deadline) {
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
    expect(engine.currentPolicy.rules.map((rule) => rule.id)).toEqual(["block-send"]);
  });
});
