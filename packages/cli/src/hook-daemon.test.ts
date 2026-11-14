import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { daemonEndpoint, parseHookArgs } from "./hook-client.js";

const dist = resolve("packages/cli/dist");

describe("parseHookArgs", () => {
  it("reads the argv that install-hooks writes and leaves anything else to commander", () => {
    expect(parseHookArgs(["-c", "/p/palizade.yaml", "hook", "claude-code"])).toEqual({ config: "/p/palizade.yaml", client: "claude-code" });
    expect(parseHookArgs(["--config=/p/x.yaml", "hook", "cursor", "beforeSubmitPrompt", "--session", "s", "--cwd=/w"])).toEqual({ config: "/p/x.yaml", client: "cursor", event: "beforeSubmitPrompt", session: "s", cwd: "/w" });
    expect(parseHookArgs(["hook", "gemini", "BeforeTool"])).toEqual({ config: "palizade.yaml", client: "gemini", event: "BeforeTool" });
    expect(parseHookArgs(["status"])).toBeUndefined();
    expect(parseHookArgs(["hook"])).toBeUndefined();
    expect(parseHookArgs(["hook", "codex", "--verbose"])).toBeUndefined();
    expect(parseHookArgs(["-c"])).toBeUndefined();
    expect(parseHookArgs(["hook", "a", "b", "c"])).toBeUndefined();
  });
});

describe("palizade daemon", () => {
  let dir: string, config: string, env: NodeJS.ProcessEnv, launcherOnly: string;
  const cases: Array<[string, string, string]> = [];

  beforeAll(async () => {
    // macOS limits socket paths to 104 bytes, and its tmpdir is long.
    dir = await mkdtemp(join(process.platform === "win32" ? tmpdir() : "/tmp", "pz-"));
    config = join(dir, "palizade.yaml");
    // The daemon's socket and key live under the home directory; keep them inside the test.
    env = { ...process.env, HOME: dir, USERPROFILE: dir };
    delete env.PALIZADE_NO_DAEMON;
    delete env.PALIZADE_RUN_ID;
    expect(spawnSync(process.execPath, [join(dist, "index.cjs"), "init"], { cwd: dir, env, encoding: "utf8" }).status).toBe(0);
    // A copy of the launcher without the main bundle can only answer through the daemon.
    launcherOnly = join(dir, "launcher");
    await mkdir(launcherOnly);
    for (const file of ["index.cjs", "hook-client.cjs"]) await copyFile(join(dist, file), join(launcherOnly, file));
    const pre = (tool: string, input: object) => JSON.stringify({ hook_event_name: "PreToolUse", session_id: "d", cwd: dir, tool_name: tool, tool_input: input });
    cases.push(
      ["claude-code", "PreToolUse", pre("Bash", { command: "ls -la" })], // allow
      ["claude-code", "PreToolUse", pre("Write", { file_path: "palizade.yaml", content: "x" })], // ask
      ["codex", "PreToolUse", pre("Write", { file_path: "palizade.yaml", content: "x" })], // ask becomes deny on Codex
      ["cursor", "beforeShellExecution", JSON.stringify({ conversation_id: "d", cwd: dir, command: "ls" })],
      ["gemini", "BeforeTool", JSON.stringify({ hook_event_name: "BeforeTool", session_id: "d", cwd: dir, tool_name: "run_shell_command", tool_input: { command: "ls" } })],
      ["claude-code", "PreToolUse", "{not json"], // error: fails closed
      ["cursor", "beforeSubmitPrompt", "{not json"] // a prompt hook error never blocks
    );
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const hook = (launcher: string, client: string, event: string, input: string, extra: NodeJS.ProcessEnv = {}) =>
    spawnSync(process.execPath, [join(launcher, "index.cjs"), "-c", config, "hook", client, event], { cwd: dir, env: { ...env, ...extra }, input, encoding: "utf8", timeout: 20000 });
  const inProcess = (client: string, event: string, input: string) => hook(dist, client, event, input, { PALIZADE_NO_DAEMON: "1" });
  const same = (actual: ReturnType<typeof hook>, expected: ReturnType<typeof hook>) => {
    expect(actual.stdout).toBe(expected.stdout);
    expect(actual.status).toBe(expected.status);
  };

  async function startDaemon(): Promise<ChildProcess> {
    const child = spawn(process.execPath, [join(dist, "index.cjs"), "-c", config, "daemon"], { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"] });
    await new Promise<void>((ok, fail) => {
      child.stdout!.once("data", () => ok());
      child.once("exit", (code) => fail(new Error(`daemon exited ${code}`)));
    });
    return child;
  }
  const stop = (child: ChildProcess, signal: NodeJS.Signals) => new Promise<void>((ok) => { child.once("exit", () => ok()); child.kill(signal); });

  it("answers exactly as the in process hook for allow, ask, deny, errors and prompts", async () => {
    const daemon = await startDaemon();
    try {
      for (const [client, event, input] of cases) {
        const expected = inProcess(client, event, input);
        const viaDaemon = hook(launcherOnly, client, event, input);
        expect(viaDaemon.stderr).toBe(expected.stderr);
        same(viaDaemon, expected);
      }
      expect(inProcess("codex", "PreToolUse", cases[2]![2]).stdout).toContain('"permissionDecision":"deny"');
      expect(inProcess("claude-code", "PreToolUse", cases[5]![2]).status).toBe(2);
      // A policy edit applies on the next call, without restarting the daemon.
      await writeFile(join(dir, "policies/default.yaml"), "version: 1\ndefaults: { action: block }\nrules: []\n");
      const blocked = hook(launcherOnly, "claude-code", "PreToolUse", cases[0]![2]);
      same(blocked, inProcess("claude-code", "PreToolUse", cases[0]![2]));
      expect(blocked.stdout).toContain("\"permissionDecision\":\"deny\"");
    } finally { await stop(daemon, "SIGTERM"); }
  }, 120000);

  it("runs in process when the daemon is gone or something else holds its socket", async () => {
    const daemon = await startDaemon();
    await stop(daemon, "SIGKILL"); // leaves a stale key and socket behind
    for (const [client, event, input] of cases) same(hook(dist, client, event, input), inProcess(client, event, input));

    // Something listening on the endpoint without the key cannot answer for Palizade.
    // The hooks run with HOME set to the test folder; on Windows the pipe name does not depend on it.
    const pipe = daemonEndpoint(config).socket;
    const socket = process.platform === "win32" ? pipe : join(dir, ".palizade", "run", basename(pipe));
    if (process.platform !== "win32") await rm(socket, { force: true });
    const forged = JSON.stringify({ body: JSON.stringify({ stdout: '{"permission":"allow"}\n', stderr: "", exitCode: 0 }), mac: "0".repeat(64) });
    let contacted = 0;
    const squatter = createServer((connection) => { contacted += 1; connection.resume(); connection.end(`${forged}\n`); });
    await new Promise<void>((ok) => squatter.listen(socket, () => ok()));
    try {
      const [client, event, input] = cases[5]!;
      // Async, so this process can answer as the squatter while the hook runs.
      const result = await new Promise<{ stdout: string; status: number | null }>((ok) => {
        const child = spawn(process.execPath, [join(dist, "index.cjs"), "-c", config, "hook", client, event], { cwd: dir, env });
        let stdout = "";
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.on("close", (status) => ok({ stdout, status }));
        child.stdin.end(input);
      });
      const expected = inProcess(client, event, input);
      expect(result.stdout).toBe(expected.stdout);
      expect(result.status).toBe(2);
      expect(contacted).toBe(1);
    } finally { await new Promise<void>((ok) => squatter.close(() => ok())); }
  }, 120000);
});
