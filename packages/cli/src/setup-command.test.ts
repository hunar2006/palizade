import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { expect, it } from "vitest";

const SERVER = `
const rl = require("node:readline").createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
rl.on("line", (line) => {
  const m = JSON.parse(line);
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "notes", version: "1" } } });
  if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "read_note", inputSchema: {} }, { name: "send_email", inputSchema: {} }] } });
});`;

it.each([
  ["workspace", []], ["npm cache", ["cache"]], ["pnpm dlx cache", ["pnpm-cache", "dlx", "fixture", "pkg", "node_modules"]],
  ["Yarn dlx cache", ["xfs-0123abcd", "dlx-101", "node_modules"]], ["bunx cache", ["bunx-1234-palizade", "node_modules"]]
])("warns when a hook will call a CLI in the %s", async (location, cacheParts) => {
  const home = await mkdtemp(join(tmpdir(), "palizade-hook-warning-"));
  try {
    const cwd = join(home, "workspace");
    const cache = join(home, "cache");
    const dist = join(location === "workspace" ? cwd : join(home, ...cacheParts), "palizade", "dist");
    await mkdir(cwd);
    await mkdir(dist, { recursive: true });
    for (const file of ["index.cjs", "cli.cjs"]) await copyFile(resolve("packages/cli/dist", file), join(dist, file));
    const settings = join(home, "settings.json");
    const result = spawnSync(process.execPath, [join(dist, "index.cjs"), "install-hooks", "claude-code", "--settings", settings], {
      cwd, encoding: "utf8", timeout: 10000,
      env: { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: join(home, ".claude"), npm_config_cache: cache }
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain(location);
    expect(await readFile(settings, "utf8")).toContain("PreToolUse");
  } finally { await rm(home, { recursive: true, force: true }); }
});

it("upgrades older Claude Code project hooks without duplicating registrations or changing unrelated hooks", async () => {
  const home = await mkdtemp(join(tmpdir(), "palizade-project-claude-"));
  try {
    const cli = resolve("packages/cli/dist/index.cjs");
    const cwd = join(home, "repository", "nested");
    const root = dirname(cwd);
    const settings = join(root, ".claude", "settings.local.json");
    await mkdir(cwd, { recursive: true });
    await mkdir(dirname(settings), { recursive: true });
    await mkdir(join(root, ".git"));
    const env = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: join(home, ".claude") };
    const run = (args: string[]) => {
      const result = spawnSync(process.execPath, [cli, ...args], { cwd, env, encoding: "utf8", timeout: 10000 });
      expect(result.status, result.stderr).toBe(0);
      return result.stdout;
    };
    run(["init"]);
    const old = { type: "command", command: process.execPath, args: [cli, "hook", "claude-code"] };
    const userHook = { type: "command", command: "echo custom" };
    const original = { hooks: {
      PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch|mcp__.*", hooks: [old, userHook] }],
      PostToolUse: [{ matcher: "Read|WebFetch|Grep|Glob|mcp__.*", hooks: [old] }],
      UserPromptSubmit: [{ hooks: [{ ...old, args: [...old.args, "UserPromptSubmit"] }] }]
    } };
    await writeFile(settings, JSON.stringify(original));
    const doctor = () => run(["doctor", "--client", "claude-code", "--project"]);
    const before = doctor();
    for (const event of Object.keys(original.hooks)) expect(before).toContain(`${event}: OUTDATED`);
    const install = () => run(["install-hooks", "claude-code", "--project"]);
    expect(install()).toContain(`Updated ${settings}`);
    expect(install()).toContain("Hooks are up to date");
    const updated = JSON.parse(await readFile(settings, "utf8"));
    expect(updated.hooks.PreToolUse).toHaveLength(2);
    expect(updated.hooks.PreToolUse[0]).toEqual({ matcher: original.hooks.PreToolUse[0]!.matcher, hooks: [userHook] });
    expect(updated.hooks.PostToolUse).toHaveLength(1);
    expect(updated.hooks.UserPromptSubmit).toHaveLength(1);
    const after = doctor();
    for (const event of Object.keys(original.hooks)) expect(after).toContain(`${event}: configured, awaiting observed execution`);
    expect(after).toContain("Warning: some hooks are awaiting observed execution");
  } finally { await rm(home, { recursive: true, force: true }); }
});

it("sets up Cursor in one step with a custom config filename, wrapped servers, hooks and tool approval", async () => {
  const home = await mkdtemp(join(tmpdir(), "palizade-setup-"));
  try {
    const work = join(home, "palizade-home");
    const configPath = join(work, "custom.yaml");
    await mkdir(join(home, ".cursor"), { recursive: true });
    await mkdir(work, { recursive: true });
    await writeFile(join(home, "server.js"), SERVER);
    await writeFile(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { notes: { command: process.execPath, args: [join(home, "server.js")] } } }));
    const originalHooks = JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "node /tools/check.js" }] } });
    await writeFile(join(home, ".cursor", "hooks.json"), originalHooks);
    const result = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", configPath, "setup", "cursor", "--lock", "--timeout", "20s"], {
      cwd: work, encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: home, USERPROFILE: home }
    });
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout).toContain("Approved 2 tool(s) for notes.");
    const client = JSON.parse(await readFile(join(home, ".cursor", "mcp.json"), "utf8")) as { mcpServers: { notes: { args: string[] } } };
    expect(client.mcpServers.notes.args).toContain("wrap");
    expect(client.mcpServers.notes.args).toContain(configPath);
    expect(await readFile(configPath, "utf8")).toContain("policy: policies/default.yaml");
    await expect(readFile(join(work, "palizade.yaml"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    const hooks = JSON.parse(await readFile(join(home, ".cursor", "hooks.json"), "utf8")) as { hooks: Record<string, unknown[]> };
    expect(Object.keys(hooks.hooks)).toEqual(expect.arrayContaining(["beforeShellExecution", "beforeSubmitPrompt"]));
    expect(await readFile(join(work, "palizade.lock"), "utf8")).toContain("send_email");

    const again = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", configPath, "setup", "cursor"], { cwd: work, encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: home, USERPROFILE: home } });
    expect(again.status).toBe(0);
    expect(again.stdout).toContain("No unprotected MCP servers found.");
    expect(again.stdout).toContain("Hooks are up to date");
    expect(await readFile(join(home, ".cursor", "hooks.json.bak"), "utf8")).toBe(originalHooks);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 90_000);

it("never blocks a prompt from the CLI, even with a missing config", () => {
  const result = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", join(tmpdir(), "palizade-missing", "palizade.yaml"), "hook", "claude-code", "UserPromptSubmit"], { input: "{\"prompt\":\"hi\"}", encoding: "utf8", timeout: 10_000 });
  expect(result.status).toBe(0);
  expect(result.stdout).toBe("");
});

it("installs project hooks in separate workspaces and reports only observations of the matching registration", async () => {
  const home = await mkdtemp(join(tmpdir(), "palizade-project-hook-"));
  try {
    const cli = resolve("packages/cli/dist/index.cjs");
    const first = join(home, "workspace one");
    const second = join(home, "workspace two");
    await mkdir(first);
    await mkdir(second);
    await mkdir(join(home, ".cursor"));
    const userSettings = join(home, ".cursor", "hooks.json");
    const original = JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "node custom.cjs" }] } });
    await writeFile(userSettings, original);
    const run = (cwd: string, args: string[], input?: string) => {
      const result = spawnSync(process.execPath, [cli, "-c", join(cwd, "palizade.yaml"), ...args], {
        cwd, ...(input === undefined ? {} : { input }), encoding: "utf8", timeout: 20000,
        env: { ...process.env, HOME: home, USERPROFILE: home, PALIZADE_NO_DAEMON: "1" }
      });
      expect(result.status, result.stderr + result.stdout).toBe(0);
      return result.stdout;
    };
    run(first, ["setup", "cursor", "--project"]);
    run(second, ["setup", "cursor", "--project"]);
    expect(await readFile(userSettings, "utf8")).toBe(original);
    const doctor = (cwd: string) => run(cwd, ["doctor", "--client", "cursor", "--project"]);
    const inspectFirst = doctor(first);
    expect(inspectFirst).toContain("beforeShellExecution: configured, awaiting observed execution");
    expect(inspectFirst).toContain(join(first, ".cursor", "hooks.json"));
    const payload = JSON.stringify({ conversation_id: "fixture", hook_event_name: "beforeShellExecution", cwd: first, command: "npm test" });
    run(first, ["hook", "cursor"], payload);
    expect(doctor(first)).toContain("beforeShellExecution: configured, awaiting observed execution");
    run(first, ["hook", "--hook-source", join(first, ".cursor", "hooks.json"), "cursor"], payload);
    expect(doctor(first)).toMatch(/beforeShellExecution: observed at \d{4}-/u);
    expect(doctor(second)).toContain("beforeShellExecution: configured, awaiting observed execution");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 30000);

it("doctor reports corrupt and unreadable canary stores without failing silently", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-doctor-canary-"));
  const home = await mkdtemp(join(tmpdir(), "palizade-doctor-home-"));
  try {
    const cli = resolve("packages/cli/dist/index.cjs");
    const env = { ...process.env, HOME: home, USERPROFILE: home, PALIZADE_NO_DAEMON: "1" };
    await writeFile(join(dir, "palizade.yaml"), "policy: policies/default.yaml\nservers: {}\n", "utf8");
    await mkdir(join(dir, ".palizade"), { recursive: true });

    const runDoctor = () => spawnSync(process.execPath, [cli, "doctor", "--client", "claude-code", "--project"], {
      cwd: dir, env, encoding: "utf8", timeout: 10000
    });

    // Missing canary store is normal.
    const missing = runDoctor();
    expect(missing.status, missing.stderr + missing.stdout).toBe(0);
    expect(missing.stdout).not.toContain("Canary store:");

    // Corrupt canary store must surface cleanly with non-zero status.
    const storePath = join(dir, ".palizade", "canaries.json");
    await writeFile(storePath, "{broken", "utf8");
    const corrupt = runDoctor();
    expect(corrupt.status).toBe(1);
    expect(corrupt.stdout + corrupt.stderr).toContain("Canary store:");

    // Unreadable canary store (directory instead of file) must surface cleanly too.
    await rm(storePath, { force: true });
    await mkdir(storePath);
    const unreadable = runDoctor();
    expect(unreadable.status).toBe(1);
    expect(unreadable.stdout + unreadable.stderr).toContain("Canary store:");
  } finally {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
