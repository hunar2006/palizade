import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";

const SERVER = `
const rl = require("node:readline").createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
rl.on("line", (line) => {
  const m = JSON.parse(line);
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "notes", version: "1" } } });
  if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "read_note", inputSchema: {} }, { name: "send_email", inputSchema: {} }] } });
});`;

it("sets up Cursor in one step: config, wrapped servers, hooks and tool approval", async () => {
  const home = await mkdtemp(join(tmpdir(), "palizade-setup-"));
  try {
    const work = join(home, "palizade-home");
    await mkdir(join(home, ".cursor"), { recursive: true });
    await mkdir(work, { recursive: true });
    await writeFile(join(home, "server.js"), SERVER);
    await writeFile(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { notes: { command: process.execPath, args: [join(home, "server.js")] } } }));
    const result = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(work, "palizade.yaml"), "setup", "cursor", "--lock", "--timeout", "20s"], {
      cwd: work, encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: home, USERPROFILE: home }
    });
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout).toContain("Approved 2 tool(s) for notes.");
    const client = JSON.parse(await readFile(join(home, ".cursor", "mcp.json"), "utf8")) as { mcpServers: { notes: { args: string[] } } };
    expect(client.mcpServers.notes.args).toContain("wrap");
    const hooks = JSON.parse(await readFile(join(home, ".cursor", "hooks.json"), "utf8")) as { hooks: Record<string, unknown[]> };
    expect(Object.keys(hooks.hooks)).toEqual(expect.arrayContaining(["beforeShellExecution", "beforeSubmitPrompt"]));
    expect(await readFile(join(work, "palizade.lock"), "utf8")).toContain("send_email");

    const again = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(work, "palizade.yaml"), "setup", "cursor"], { cwd: work, encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: home, USERPROFILE: home } });
    expect(again.status).toBe(0);
    expect(again.stdout).toContain("No unprotected MCP servers found.");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 90_000);

it("never blocks a prompt from the CLI, even with a missing config", () => {
  const result = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(tmpdir(), "palizade-missing", "palizade.yaml"), "hook", "claude-code", "UserPromptSubmit"], { input: "{\"prompt\":\"hi\"}", encoding: "utf8", timeout: 10_000 });
  expect(result.status).toBe(0);
  expect(result.stdout).toBe("");
});
