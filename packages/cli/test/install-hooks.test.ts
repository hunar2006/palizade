import { spawnSync } from "node:child_process";
import { copyFile, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { inspectHooks, installHooks, mergeHookEntries } from "../src/install-hooks.js";

const cliParts = ["C:/node/node.exe", "C:/palizade/dist/index.cjs", "-c", "C:/proj/palizade.yaml", "hook"];
const systemPowerShell = join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

function hookScript(command: string): string {
  const encoded = /FromBase64String\('([\w+/=]+)'\)/u.exec(command)?.[1];
  return encoded ? Buffer.from(encoded, "base64").toString("utf16le") : command;
}

function shellHook(client: string, event: string, parts: string[]): { command: string; timeout: number } {
  const settings = mergeHookEntries(client, {}, parts, "unused");
  const hooks = settings.hooks as Record<string, Array<{ hooks: Array<{ command: string; timeout: number }> }>>;
  return hooks[event]![0]!.hooks[0]!;
}

describe("mergeHookEntries", () => {
  it.each([["codex", "PostToolUse", "Bash"], ["gemini", "AfterTool", "run_shell_command"]])("includes %s shell output on %s", (client, event, tool) => {
    const { hooks } = mergeHookEntries(client, {}, cliParts, "unused");
    const groups = hooks as Record<string, Array<{ matcher: string }>>;
    expect(groups[event]![0]!.matcher.split("|")).toContain(tool);
  });

  it.each([["codex", "PostToolUse", 45], ["gemini", "AfterTool", 45000]] as const)("gives %s more time than the internal hook timeout", (client, event, timeout) => {
    expect(shellHook(client, event, cliParts).timeout).toBe(timeout);
  });

  it.each([["codex", "PreToolUse", 75], ["gemini", "BeforeTool", 75000]] as const)("uses the configured %s hook timeout plus margin", async (client, event, timeout) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-hook-timeout-"));
    try {
      const configPath = join(dir, "palizade.yaml");
      const settingsPath = join(dir, "settings.json");
      await writeFile(configPath, "hooks: { timeoutMs: 60000 }\n");
      const result = await installHooks(client, { configPath, settingsPath, cwd: dir });
      expect(JSON.parse(result.configJson).hooks[event][0].hooks[0].timeout).toBe(timeout);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("adds Claude Code PreToolUse/PostToolUse entries without duplicating", () => {
    const settings = { permissions: { allow: [] } };
    const merged = mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, unknown[]>;
    expect(hooks.PreToolUse).toHaveLength(1);
    expect(hooks.PostToolUse).toHaveLength(1);
    expect(hooks.PreToolUse[0]).toMatchObject({ matcher: "^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|mcp__.*)$" });
    const hook = (hooks.PreToolUse[0] as { hooks: Array<{ command: string; args: string[] }> }).hooks[0]!;
    expect(hook.command).toBe("C:/node/node.exe");
    expect(hook.args).toContain("hook");
    expect(hook.args).toContain("claude-code");

    const mergedAgain = mergeHookEntries("claude-code", merged, cliParts, "C:/proj/palizade.yaml");
    expect((mergedAgain.hooks as Record<string, unknown[]>).PreToolUse).toHaveLength(1);
    expect(mergedAgain.permissions).toEqual({ allow: [] });
  });

  it("adds Cursor beforeShellExecution/beforeMCPExecution with failClosed", () => {
    const merged = mergeHookEntries("cursor", {}, cliParts, "C:/proj/palizade.yaml");
    expect(merged.version).toBe(1);
    const hooks = merged.hooks as Record<string, Array<{ command: string; failClosed?: boolean }>>;
    expect(hooks.beforeShellExecution).toHaveLength(1);
    expect(hooks.beforeShellExecution[0]?.failClosed).toBe(true);
    expect(hookScript(hooks.beforeShellExecution[0]!.command)).toContain("hook");
    expect(hooks.beforeMCPExecution[0]?.failClosed).toBe(true);
  });

  it("adds Codex PreToolUse entries with a Bash/apply_patch matcher", () => {
    const merged = mergeHookEntries("codex", {}, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, unknown[]>;
    expect(hooks.PreToolUse[0]).toMatchObject({ matcher: "Bash|apply_patch|mcp__.*" });
    const group = hooks.PreToolUse[0] as { hooks: Array<{ command: string; args?: string[] }> };
    expect(group.hooks[0]?.command).toContain(process.platform === "win32" ? "powershell.exe" : "hook codex");
    expect(group.hooks[0]?.args).toBeUndefined();
  });

  it("adds prompt hooks, fails Claude Code tool hooks closed, and updates old entries in place", () => {
    const old = { hooks: { PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch", hooks: [{ type: "command", command: "C:/node/node.exe", args: [...cliParts.slice(1), "claude-code"] }] }] } };
    const merged = mergeHookEntries("claude-code", old, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, Array<{ hooks: Array<{ args: string[]; onFailure?: string }> }>>;
    expect(hooks.PreToolUse).toHaveLength(1);
    expect(hooks.PreToolUse[0]!.hooks[0]!.onFailure).toBe("block");
    expect(hooks.UserPromptSubmit[0]!.hooks[0]!.args.slice(-2)).toEqual(["claude-code", "UserPromptSubmit"]);
    expect(hooks.UserPromptSubmit[0]!.hooks[0]!.onFailure).toBeUndefined();

    const cursor = mergeHookEntries("cursor", mergeHookEntries("cursor", {}, cliParts, "x"), cliParts, "x");
    const cursorHooks = cursor.hooks as Record<string, Array<{ command: string; failClosed?: boolean }>>;
    expect(cursorHooks.beforeShellExecution).toHaveLength(1);
    expect(cursorHooks.beforeSubmitPrompt).toHaveLength(1);
    expect(hookScript(cursorHooks.beforeSubmitPrompt[0]!.command)).toContain("beforeSubmitPrompt");
    expect(cursorHooks.beforeSubmitPrompt[0]!.failClosed).toBeUndefined();

    const codex = mergeHookEntries("codex", {}, cliParts, "x").hooks as Record<string, unknown[]>;
    expect(codex.UserPromptSubmit).toHaveLength(1);
  });

  it("adds Gemini CLI hooks as shell command lines and updates them in place", () => {
    const merged = mergeHookEntries("gemini", { general: { vimMode: true } }, cliParts, "x");
    const hooks = merged.hooks as Record<string, Array<{ matcher?: string; hooks: Array<{ type: string; command: string; timeout: number }> }>>;
    expect(merged.general).toEqual({ vimMode: true });
    expect(Object.keys(hooks)).toEqual(["BeforeTool", "AfterTool", "BeforeAgent"]);
    expect(hooks.BeforeTool[0]!.matcher).toContain("mcp_.*");
    expect(hooks.BeforeTool[0]!.hooks[0]!.command).toContain(process.platform === "win32" ? "powershell.exe" : "gemini BeforeTool");
    const again = mergeHookEntries("gemini", merged, cliParts, "x").hooks as Record<string, unknown[]>;
    expect(again.BeforeTool).toHaveLength(1);
  });

  it("preserves existing hooks and refuses malformed settings", () => {
    const settings = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }] } };
    const merged = mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const pre = (merged.hooks as Record<string, unknown[]>).PreToolUse!;
    expect(pre).toHaveLength(2);
    expect(pre[0]).toMatchObject({ matcher: "Bash" });
  });

  it("preserves user hooks and their matcher when updating a mixed group", () => {
    const custom = { type: "command", command: "node", args: ["/tools/lint.js", "hook"] };
    const previous = { type: "command", command: cliParts[0], args: [...cliParts.slice(1), "claude-code"] };
    const customOnly = { matcher: "Edit", hooks: [custom] };
    const settings = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [custom, previous] }, customOnly] } };
    const install = () => mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const pre = (install().hooks as Record<string, unknown[]>).PreToolUse!;
    expect(pre).toEqual([
      { matcher: "Bash", hooks: [custom] },
      expect.objectContaining({ matcher: "^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|mcp__.*)$" }),
      customOnly
    ]);
    expect((install().hooks as Record<string, unknown[]>).PreToolUse).toHaveLength(3);
  });

  it.skipIf(process.platform !== "win32")("runs Cursor's updated Windows command through PowerShell and preserves argv and exit status", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-install-hooks-"));
    try {
      const script = join(dir, "Workspace's $files", "palizade", "dist", "index.cjs");
      const config = join(dir, "policy's $file.yaml");
      await mkdir(dirname(script), { recursive: true });
      await writeFile(script, "process.stdout.write(JSON.stringify(process.argv.slice(2))); process.exitCode = 2;");
      const settingsPath = join(dir, "hooks.json");
      const oldCommand = `"${process.execPath}" "${script}" -c "${config}" hook cursor beforeSubmitPrompt`;
      const settings = { version: 1, hooks: { beforeSubmitPrompt: [{ command: oldCommand }] } };
      await writeFile(settingsPath, JSON.stringify(settings));
      expect((await inspectHooks("cursor", settingsPath)).events.find((entry) => entry.event === "beforeSubmitPrompt")?.status).toBe("outdated");

      const parts = [process.execPath, script, "-c", config, "hook"];
      const current = mergeHookEntries("cursor", {}, parts, config).hooks as typeof settings.hooks;
      const previous = hookScript(current.beforeSubmitPrompt[0]!.command);
      expect(previous).toMatch(/^& \{/u);
      settings.hooks.beforeSubmitPrompt = [{ command: previous }];
      await writeFile(settingsPath, JSON.stringify(settings));
      expect((await inspectHooks("cursor", settingsPath)).events.find((entry) => entry.event === "beforeSubmitPrompt")?.status).toBe("outdated");
      settings.hooks.beforeSubmitPrompt.push({ command: oldCommand });
      mergeHookEntries("cursor", settings, parts, config);
      mergeHookEntries("cursor", settings, parts, config);
      expect(settings.hooks.beforeSubmitPrompt).toHaveLength(1);
      const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", settings.hooks.beforeSubmitPrompt[0]!.command],
        { encoding: "utf8", timeout: 10000 });
      expect(result.status, result.stderr).toBe(2);
      expect(JSON.parse(result.stdout)).toEqual(["-c", config, "hook", "cursor", "beforeSubmitPrompt"]);
      await writeFile(settingsPath, JSON.stringify(settings));
      expect((await inspectHooks("cursor", settingsPath)).events.every((entry) => entry.status === "installed")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([
    { client: "codex", event: "UserPromptSubmit" },
    { client: "gemini", event: "BeforeAgent" }
  ])("runs $client's command through the configured shell and updates old hooks in place", async ({ client, event }) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-shell-hooks-"));
    try {
      const config = join(dir, "policy's $file.yaml");
      const script = join(dir, "Workspace's $files", "palizade", "dist", "index.cjs");
      await mkdir(dirname(script), { recursive: true });
      await writeFile(script, "process.stdin.once('data', input => process.stdout.write(JSON.stringify([process.argv.slice(2), input.toString()])));");
      const args = [script, "-c", config, "hook", client, event];
      const legacy = client === "codex"
        ? { type: "command", command: process.execPath, args, timeout: 30 }
        : { type: "command", name: "palizade", command: `"${process.execPath}" "${script}" -c "${config}" hook gemini ${event}`, timeout: 30000 };
      const groups = [{ hooks: [legacy] }];
      const settings = { hooks: { [event]: groups } };
      const settingsPath = join(dir, "hooks.json");
      await writeFile(settingsPath, JSON.stringify(settings));
      if (client === "codex" || process.platform === "win32") {
        expect((await inspectHooks(client, settingsPath)).events.find((entry) => entry.event === event)?.status).toBe("outdated");
      }

      const parts = [process.execPath, ...args.slice(0, 4)];
      mergeHookEntries(client, settings, parts, config);
      mergeHookEntries(client, settings, parts, config);
      expect(groups).toHaveLength(1);
      const [handler] = groups[0]!.hooks;
      expect(handler?.args).toBeUndefined();
      const command = handler!.command;
      const input = "sample café input\n";
      const options = { input, encoding: "utf8" as const, timeout: 10000 };
      const results = process.platform === "win32"
        ? [
            spawnSync("cmd.exe", ["/D", "/C", `"${command}"`], { ...options, windowsVerbatimArguments: true }),
            spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], options)
          ]
        : [spawnSync("/bin/sh", ["-c", command], options)];
      for (const result of results) {
        expect(result.status, result.stderr).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual([args.slice(1), input]);
      }
      await writeFile(settingsPath, JSON.stringify(settings));
      expect((await inspectHooks(client, settingsPath)).events.every((entry) => entry.status === "installed")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(process.platform !== "win32")("Windows hook command", () => {
  const runPowerShell = (script: string, options: { cwd?: string } = {}) =>
    spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")],
      { ...options, encoding: "utf8" as const, timeout: 10000 });

  it.each([
    ["IDE", 0], ["IDE", 2], ["agent host", 0], ["agent host", 2]
  ] as const)("passes Cursor %s stdin and exit %i", async (mode, exitCode) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-cursor-pipe-"));
    try {
      const script = join(dir, "index.cjs");
      const input = JSON.stringify({ hook_event_name: "beforeShellExecution", command: "npm test caf\u00e9" });
      await writeFile(script, `const input = require("node:fs").readFileSync(0); process.stdout.write(input.toString("base64")); process.exitCode = ${exitCode};`);
      await writeFile(join(dir, "payload.json"), `\uFEFF${input}`);
      const { hooks } = mergeHookEntries("cursor", {}, [process.execPath, script, "hook"], "unused");
      const { command } = (hooks as Record<string, { command: string }[]>).beforeShellExecution![0]!;
      const line = mode === "IDE"
        ? `Get-Content payload.json | & { $input | ${command} }`
        : `@'\n${input}\n'@ | & ${command}`;
      const bom = mode === "agent host";
      const result = runPowerShell(
        `if ([Console]::InputEncoding.GetPreamble().Length -gt 0) { [Console]::InputEncoding = [Text.UTF8Encoding]::new($false) }\n$OutputEncoding = [Text.UTF8Encoding]::new($${bom})\n${line}`,
        { cwd: dir }
      );
      expect(result.status, result.stderr).toBe(exitCode);
      expect(Buffer.from(result.stdout.trim(), "base64")).toEqual(Buffer.from(`${bom ? "\uFEFF" : ""}${input}\r\n`));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("Cursor Windows wrapper itself adds zero BOM bytes under any console code page", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-cursor-direct-"));
    try {
      const script = join(dir, "index.cjs");
      const input = JSON.stringify({ hook_event_name: "beforeShellExecution", command: "npm test" });
      await writeFile(script, `const input = require("node:fs").readFileSync(0); process.stdout.write(input.toString("base64"));`);
      const { hooks } = mergeHookEntries("cursor", {}, [process.execPath, script, "hook"], "unused");
      const { command } = (hooks as Record<string, { command: string }[]>).beforeShellExecution![0]!;
      const result = spawnSync("cmd.exe", ["/D", "/C", `"${command}"`], {
        cwd: dir,
        input: Buffer.from(input, "utf8"),
        encoding: "utf8",
        windowsVerbatimArguments: true,
        timeout: 10000
      });
      expect(result.status, result.stderr).toBe(0);
      expect(Buffer.from(result.stdout.trim(), "base64")).toEqual(Buffer.from(input, "utf8"));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([["codex", "PreToolUse"], ["gemini", "BeforeTool"]])("forwards %s exit 2 from every Windows launch mode", async (client, event) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-shell-status-"));
    try {
      const script = join(dir, "index.cjs");
      await writeFile(script, "process.stdout.write('node ran'); process.exitCode = 2;");
      const { command } = shellHook(client, event, [process.execPath, script, "hook"]);
      const options = { encoding: "utf8" as const, timeout: 10000 };
      const [, launcher, bootstrap] = /^(\S+) -NoProfile -NonInteractive -Command "([^"]+)"/u.exec(command)!;
      const direct = spawnSync(launcher!, ["-NoProfile", "-NonInteractive", "-Command", bootstrap!], options);
      const cmd = spawnSync("cmd.exe", ["/D", "/C", `"${command}"`], { ...options, windowsVerbatimArguments: true });
      const powershell = runPowerShell(command);
      for (const run of [direct, cmd, powershell]) {
        expect(run.status, run.stderr).toBe(2);
        expect(run.stdout).toBe("node ran");
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([
    ["IDE", 0], ["IDE", 2], ["agent host", 0], ["agent host", 2]
  ] as const)("runs built CLI through Cursor %s Windows transport with BOM input (exit %i)", async (mode, expectedExit) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-cursor-built-"));
    try {
      const cli = resolve("packages/cli/dist/index.cjs");
      const configPath = join(dir, "palizade.yaml");
      await writeFile(configPath, `policy: ${JSON.stringify(resolve("policies/default.yaml"))}\nservers: {}\nhooks: { failMode: closed }\n`, "utf8");
      const validPayload = JSON.stringify({
        hook_event_name: "beforeShellExecution",
        conversation_id: "cursor-bom-e2e",
        cwd: dir,
        command: "npm test caf\u00e9"
      });
      // For exit 2, send invalid JSON prefixed with BOM so built CLI parses BOM then fails closed to exit 2.
      const body = expectedExit === 0 ? validPayload : "{not-json";
      await writeFile(join(dir, "payload.json"), `\uFEFF${body}`, "utf8");
      const { hooks } = mergeHookEntries("cursor", {}, [process.execPath, cli, "-c", configPath, "hook"], configPath);
      const { command } = (hooks as Record<string, { command: string }[]>).beforeShellExecution![0]!;
      const line = mode === "IDE"
        ? `Get-Content payload.json | & { $input | ${command} }`
        : `@'\n${body}\n'@ | & ${command}`;
      const bom = mode === "agent host";
      const result = runPowerShell(`$OutputEncoding = [Text.UTF8Encoding]::new($${bom})\n${line}`, { cwd: dir });
      expect(result.status, result.stderr + result.stdout).toBe(expectedExit);
      if (expectedExit === 2) {
        expect(JSON.parse(result.stdout.trim())).toMatchObject({ permission: "deny" });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("runs built CLI through Cursor Windows transport with two leading BOMs (exit 0)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-cursor-2bom-"));
    try {
      const cli = resolve("packages/cli/dist/index.cjs");
      const configPath = join(dir, "palizade.yaml");
      await writeFile(configPath, `policy: ${JSON.stringify(resolve("policies/default.yaml"))}\nservers: {}\nhooks: { failMode: closed }\n`, "utf8");
      const validPayload = JSON.stringify({
        hook_event_name: "beforeShellExecution",
        conversation_id: "cursor-2bom-e2e",
        cwd: dir,
        command: "npm test caf\u00e9"
      });
      const { hooks } = mergeHookEntries("cursor", {}, [process.execPath, cli, "-c", configPath, "hook"], configPath);
      const { command } = (hooks as Record<string, { command: string }[]>).beforeShellExecution![0]!;
      const line = `@'\n\uFEFF${validPayload}\n'@ | & ${command}`;
      const result = runPowerShell(`$OutputEncoding = [Text.UTF8Encoding]::new($true)\n${line}`, { cwd: dir });
      expect(result.status, result.stderr + result.stdout).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fails closed when the Windows bootstrap runs in Constrained Language Mode", () => {
    const { command } = shellHook("gemini", "BeforeTool", cliParts);
    const bootstrap = / -Command "([^"]+)"/u.exec(command)![1];
    const result = runPowerShell(`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
$ExecutionContext.SessionState.LanguageMode
${bootstrap}`);
    expect(result.stdout.trim()).toBe("ConstrainedLanguage");
    expect(result.status, result.stderr).toBe(2);
  });

  it.each(["node.exe", "index.cjs"])("exits 2 when %s is missing", async (missing) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-runtime-"));
    try {
      const script = join(dir, "index.cjs");
      if (missing === "node.exe") await writeFile(script, "");
      const node = missing === "node.exe" ? join(dir, "node.exe") : process.execPath;
      const parts = [node, script, "hook"];
      const codex = shellHook("codex", "PreToolUse", parts).command;
      const gemini = shellHook("gemini", "BeforeTool", parts).command;
      const options = { encoding: "utf8" as const, timeout: 10000 };
      const run = missing === "node.exe"
        ? spawnSync("cmd.exe", ["/D", "/C", `"${codex}"`], { ...options, windowsVerbatimArguments: true })
        : spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive", "-Command", gemini], options);
      expect(run.status, run.stderr).toBe(2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("passes Windows path metacharacters literally to the intended script", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-path-"));
    try {
      const script = join(dir, "Palizade's \u2018\u2019\u201A\u201B & %PATH% !PATH! `$files $(fixture); {[x]} \u0451\u4e2d", "index.cjs");
      const config = join(dirname(script), "palizade.yaml");
      await mkdir(dirname(script));
      await writeFile(script, "process.stdout.write(JSON.stringify(process.argv.slice(2)));");
      const { command } = shellHook("gemini", "AfterTool", [process.execPath, script, "-c", config, "hook"]);
      const options = { cwd: dir, encoding: "utf8" as const, timeout: 10000 };
      const runs = [
        spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive", "-Command", command], options),
        spawnSync("cmd.exe", ["/D", "/V:ON", "/C", `"${command}"`], { ...options, windowsVerbatimArguments: true })
      ];
      for (const run of runs) {
        expect(run.status, run.stderr).toBe(0);
        expect(run.stderr).toBe("");
        expect(JSON.parse(run.stdout)).toEqual(["-c", config, "hook", "gemini", "AfterTool"]);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("uses system PowerShell even when the working directory has a powershell.exe", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-shell-path-"));
    try {
      const script = join(dir, "index.cjs");
      await copyFile(process.execPath, join(dir, "powershell.exe"));
      await writeFile(script, "process.stdout.write('system wrapper ran');");
      const { command } = shellHook("codex", "PreToolUse", [process.execPath, script, "hook"]);
      const run = spawnSync("cmd.exe", ["/D", "/C", `"${command}"`], {
        cwd: dir, encoding: "utf8", timeout: 10000, windowsVerbatimArguments: true,
        env: { ...process.env, PATH: `${dir};${process.env.PATH}` }
      });
      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).toBe("system wrapper ran");
      expect(command.split(" -NoProfile ")[0]?.toLowerCase()).toBe(systemPowerShell.toLowerCase());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each(["parent segment", "missing launcher"])("refuses a SystemRoot with a %s", async (reason) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-system-root-"));
    const root = process.env.SystemRoot || "C:\\Windows";
    try {
      vi.stubEnv("SystemRoot", reason === "parent segment" ? `${root}\\System32\\..` : dir);
      expect(() => shellHook("codex", "PreToolUse", cliParts)).toThrow(reason === "parent segment" ? /SystemRoot/u : /powershell\.exe/iu);
    } finally {
      vi.unstubAllEnvs();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("updates a legacy relative PowerShell command and preserves a separate user hook", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-legacy-launcher-"));
    try {
      const path = join(dir, "hooks.json");
      const oldScript = "& 'C:/node/node.exe' 'C:/palizade/dist/index.cjs' '-c' 'C:/proj/palizade.yaml' 'hook' 'codex'; exit $LASTEXITCODE";
      const legacy = `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(oldScript, "utf16le").toString("base64")}`;
      const custom = { matcher: "Bash", hooks: [{ type: "command", command: "echo custom" }] };
      const settings = { hooks: { PostToolUse: [custom, { matcher: "Read|WebFetch|Grep|Glob|mcp__.*", hooks: [{ type: "command", command: legacy, timeout: 30 }] }] } };
      const previous = shellHook("codex", "PostToolUse", cliParts).command.replace("trap { exit 2 }; ", "");
      settings.hooks.PostToolUse.push({ matcher: "Read|WebFetch|Grep|Glob|Bash|mcp__.*", hooks: [{ type: "command", command: previous, timeout: 45 }] });
      await writeFile(path, JSON.stringify(settings));
      const status = async () => (await inspectHooks("codex", path)).events.find((entry) => entry.event === "PostToolUse")?.status;
      expect(await status()).toBe("outdated");
      const install = () => spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "install-hooks", "codex", "--settings", path], {
        cwd: dir, encoding: "utf8", timeout: 10000,
        env: { ...process.env, HOME: dir, USERPROFILE: dir, CODEX_HOME: join(dir, ".codex"), CLAUDE_CONFIG_DIR: join(dir, ".claude") }
      });
      const first = install();
      expect(first.status, first.stderr).toBe(0);
      const updated = JSON.parse(await readFile(path, "utf8"));
      expect(updated.hooks.PostToolUse).toHaveLength(2);
      expect(updated.hooks.PostToolUse[0]).toEqual(custom);
      expect(updated.hooks.PostToolUse[1].hooks[0].command).toMatch(/^.:\\.*powershell\.exe /iu);
      expect(await status()).toBe("installed");
      const second = install();
      expect(second.status, second.stderr).toBe(0);
      expect(second.stdout).toContain("Hooks are up to date");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("project hooks", () => {
  it("installs Claude Code settings at the linked worktree's main checkout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-linked-worktree-"));
    try {
      const main = join(dir, "main");
      const worktree = join(dir, "linked");
      const gitfile = join(worktree, ".git");
      const gitDir = join(main, ".git", "worktrees", "linked");
      const cwd = join(worktree, "nested");
      await mkdir(cwd, { recursive: true });
      await mkdir(gitDir, { recursive: true });
      await writeFile(gitfile, "gitdir: ../main/.git/worktrees/linked\n");
      await writeFile(join(gitDir, "commondir"), "../..\n");
      await writeFile(join(gitDir, "gitdir"), `${gitfile}\n`);
      const result = await installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd });
      expect(result.settingsPath).toBe(join(main, ".claude", "settings.local.json"));
      expect(await readFile(result.settingsPath, "utf8")).toContain("PreToolUse");
      await expect(readFile(join(worktree, ".claude", "settings.local.json"))).rejects.toMatchObject({ code: "ENOENT" });
      for (const verb of ["install-hooks", "setup"]) {
        const cli = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), verb, "claude-code", "--project", "--dry-run"], {
          cwd, encoding: "utf8", timeout: 10000,
          env: { ...process.env, HOME: dir, USERPROFILE: dir, CLAUDE_CONFIG_DIR: join(dir, "user-claude") }
        });
        expect(cli.status, cli.stderr).toBe(0);
        const output = cli.stdout + cli.stderr;
        expect(output.replaceAll("\\\\", "\\")).toContain(result.settingsPath);
        expect(output).toContain(`Launch claude from ${main}`);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("falls back to the worktree root when the gitdir metadata is incomplete", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-project-root-"));
    try {
      const cwd = join(dir, "nested", "deeper");
      await mkdir(cwd, { recursive: true });
      await writeFile(join(dir, ".git"), "gitdir: mock-worktree\n");
      const result = await installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd });
      expect(result.settingsPath).toBe(join(dir, ".claude", "settings.local.json"));
      expect(await readFile(result.settingsPath, "utf8")).toContain("PreToolUse");
      await expect(readFile(join(cwd, ".claude", "settings.local.json"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each(["settings.local.json", "settings.local.json.bak"])("refuses a hard-linked project %s", async (name) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-project-hardlink-"));
    try {
      const project = join(dir, "project");
      const settings = join(project, ".claude", "settings.local.json");
      const target = join(dir, "synthetic-profile.json");
      const original = '{"keep":"fixture"}';
      await mkdir(dirname(settings), { recursive: true });
      await mkdir(join(project, ".git"));
      await writeFile(target, original);
      if (name.endsWith(".bak")) await writeFile(settings, "{}");
      await link(target, join(dirname(settings), name));
      await expect(installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd: project })).rejects.toThrow(/hard.link/iu);
      expect(await readFile(target, "utf8")).toBe(original);
      expect(await readFile(settings, "utf8")).toBe(name.endsWith(".bak") ? "{}" : original);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports falling back to the current directory outside a git repository", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-no-project-root-"));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const result = await installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd: dir });
      expect(result.settingsPath).toBe(join(dir, ".claude", "settings.local.json"));
      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no git repository.*current directory/iu));
    } finally {
      warn.mockRestore();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses a symlinked project settings file before writing it or creating a backup", async ({ skip }) => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-project-symlink-"));
    try {
      const settings = join(dir, ".claude", "settings.local.json");
      const target = join(dir, "synthetic-profile.json");
      const original = '{"keep":"fixture"}';
      await mkdir(dirname(settings));
      await mkdir(join(dir, ".git"));
      await writeFile(target, original);
      try {
        await symlink(target, settings, "file");
      } catch (error) {
        if (process.platform === "win32" && (error as NodeJS.ErrnoException).code === "EPERM") {
          skip("Windows file symlink creation requires additional privileges");
          return;
        }
        throw error;
      }
      await expect(installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd: dir })).rejects.toThrow(/symlink/iu);
      expect(await readFile(target, "utf8")).toBe(original);
      await expect(readFile(`${settings}.bak`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses a symlinked project settings directory before writing it or creating a backup", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-project-symlink-"));
    try {
      const target = join(dir, "synthetic-profile");
      const settings = join(target, "settings.local.json");
      const original = '{"keep":"fixture"}';
      await mkdir(target);
      await mkdir(join(dir, ".git"));
      await writeFile(settings, original);
      await symlink(target, join(dir, ".claude"), process.platform === "win32" ? "junction" : "dir");
      await expect(installHooks("claude-code", { configPath: "palizade.yaml", project: true, cwd: dir })).rejects.toThrow(/symlink/iu);
      expect(await readFile(settings, "utf8")).toBe(original);
      await expect(readFile(`${settings}.bak`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("inspectHooks", () => {
  it("reports a second stale group even after a current group and removes it on reinstall", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-duplicate-hooks-"));
    try {
      const configPath = join(dir, "palizade.yaml");
      const settingsPath = join(dir, ".claude", "settings.local.json");
      await writeFile(configPath, "{}");
      const cli = resolve("packages/cli/dist/index.cjs");
      const run = (...args: string[]) => spawnSync(process.execPath, [cli, "-c", configPath, ...args], {
        cwd: dir, encoding: "utf8", timeout: 10000,
        env: { ...process.env, HOME: dir, USERPROFILE: dir, CLAUDE_CONFIG_DIR: join(dir, "user-claude") }
      });
      const install = () => {
        const result = run("install-hooks", "claude-code", "--project");
        expect(result.status, result.stderr).toBe(0);
        return result.stdout;
      };
      install();
      const settings = JSON.parse(await readFile(settingsPath, "utf8"));
      const legacy = { type: "command", command: "palizade hook claude-code" };
      const custom = { type: "command", command: "custom-hook" };
      settings.hooks.PreToolUse.push({ matcher: "Bash", hooks: [legacy] }, { matcher: "Edit", hooks: [custom, legacy] });
      await writeFile(settingsPath, JSON.stringify(settings));
      const status = async () => (await inspectHooks("claude-code", settingsPath)).events.find((entry) => entry.event === "PreToolUse")?.status;
      expect(await status()).toBe("outdated");
      expect(run("doctor", "--client", "claude-code", "--project").stdout).toContain("PreToolUse: OUTDATED");
      install();
      const updated = JSON.parse(await readFile(settingsPath, "utf8"));
      expect(updated.hooks.PreToolUse).toEqual([settings.hooks.PreToolUse[0], { matcher: "Edit", hooks: [custom] }]);
      expect(await status()).toBe("installed");
      expect(install()).toContain("Hooks are up to date");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports the previous anchored Claude Code result matcher as outdated and replaces it on reinstall", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-upgrade-hooks-"));
    try {
      const settingsPath = join(dir, "settings.json");
      const configPath = join(dir, "palizade.yaml");
      await writeFile(configPath, "{}");
      const runCli = (...args: string[]) => spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", configPath, ...args], {
        cwd: dir, encoding: "utf8", timeout: 10000, env: { ...process.env, CLAUDE_CONFIG_DIR: dir }
      });
      const install = () => {
        const result = runCli("install-hooks", "claude-code", "--settings", settingsPath);
        expect(result.status, result.stderr).toBe(0);
      };
      install();
      const settings = JSON.parse(await readFile(settingsPath, "utf8"));
      const custom = { matcher: "Agent", hooks: [{ type: "command", command: "custom-hook" }] };
      settings.hooks.PostToolUse[0].matcher = "^(Read|WebFetch|WebSearch|Grep|Glob|Bash|PowerShell|mcp__.*)$";
      settings.hooks.PostToolUse.push(custom);
      await writeFile(settingsPath, JSON.stringify(settings));

      const status = async () => (await inspectHooks("claude-code", settingsPath)).events.find((entry) => entry.event === "PostToolUse")?.status;
      const doctor = () => runCli("doctor", "--client", "claude-code", "--client-config", settingsPath).stdout;
      expect(await status()).toBe("outdated");
      expect(doctor()).toContain("PostToolUse: OUTDATED");
      install();
      expect(await status()).toBe("installed");
      expect(doctor()).toContain("PostToolUse: configured, awaiting observed execution");
      const updated = JSON.parse(await readFile(settingsPath, "utf8")).hooks;
      expect(updated.PostToolUse).toHaveLength(2);
      expect(updated.PostToolUse).toContainEqual(custom);
      expect(updated.PreToolUse).toEqual(settings.hooks.PreToolUse);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports missing, outdated and installed entries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-inspect-hooks-"));
    try {
      const path = join(dir, "settings.json");
      expect((await inspectHooks("claude-code", path)).events.every((entry) => entry.status === "missing")).toBe(true);
      const old = { hooks: { PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch", hooks: [{ type: "command", command: "node", args: ["/x/palizade/dist/index.cjs", "hook", "claude-code"] }] }] } };
      await writeFile(path, JSON.stringify(old));
      const before = Object.fromEntries((await inspectHooks("claude-code", path)).events.map((entry) => [entry.event, entry.status]));
      expect(before).toEqual({ PreToolUse: "outdated", PostToolUse: "missing", UserPromptSubmit: "missing" });
      await writeFile(path, JSON.stringify(mergeHookEntries("claude-code", old, cliParts, "x")));
      expect((await inspectHooks("claude-code", path)).events.every((entry) => entry.status === "installed")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
