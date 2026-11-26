import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { expect, it } from "vitest";
import { DAEMON_MAX_INPUT_BYTES, daemonEndpoint } from "./hook-client.js";

it.each(["claude-code", "cursor", "codex"])("prints %s deny decisions and exits 2 for all closed-mode hook errors", async (client) => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-hook-cli-"));
  const config = join(dir, "palizade.yaml");
  const event = client === "cursor" ? "beforeShellExecution" : "PreToolUse";
  const run = (input: string) => spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", config, "hook", client, event], { input, encoding: "utf8", timeout: 10000 });
  try {
    const check = (input: string) => {
      const result = run(input);
      expect(result.status, result.stderr).toBe(2);
      const output = JSON.parse(result.stdout);
      expect(client === "cursor" ? output.permission : output.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(result.stdout + result.stderr).not.toContain("PRIVATE_INPUT");
    };
    check("{}"); // Missing config.
    await writeFile(config, "servers: []\n");
    check("{}"); // Invalid config.
    await writeFile(config, "servers: {}\nhooks: { failMode: closed, maxInputBytes: 1024 }\n");
    check("PRIVATE_INPUT".repeat(200)); // Oversized stdin.
    check("{PRIVATE_INPUT"); // Invalid JSON.
    check('{"tool_name":"Bash","tool_input":{"command":"npm test"},"command":"npm test"}'); // Missing policy during evaluation.
    await writeFile(config, "servers: {}\nhooks: { failMode: open, maxInputBytes: 1024 }\n");
    const open = run("{PRIVATE_INPUT");
    expect(open.status).toBe(0);
    expect(open.stdout).toBe("");
  } finally { await rm(dir, { recursive: true, force: true }); }
}, 20000);

it("reads the entire allowed hook input when it exceeds the daemon limit", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-hook-stdin-"));
  try {
    const config = join(dir, "palizade.yaml");
    await writeFile(config, "policy: policy.yaml\nservers: {}\nhooks: { maxInputBytes: 12582912 }\n");
    await writeFile(join(dir, "policy.yaml"), "version: 1\ndefaults: { action: allow }\nrules: []\n");
    const keyFile = join(dir, ".palizade", "run", basename(daemonEndpoint(config).keyFile));
    await mkdir(dirname(keyFile), { recursive: true });
    await writeFile(keyFile, "ab".repeat(32));
    const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "npm test" }, note: "a".repeat(DAEMON_MAX_INPUT_BYTES + 1) });
    const result = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", config, "hook", "claude-code", "PreToolUse"], {
      input, encoding: "utf8", timeout: 10000, env: { ...process.env, HOME: dir, USERPROFILE: dir, PALIZADE_NO_DAEMON: "" }
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout + result.stderr).toBe("");
  } finally { await rm(dir, { recursive: true, force: true }); }
}, 20000);

it("records taint from both ends of an oversized PostToolUse while denying oversized PreToolUse", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-post-hook-stdin-"));
  try {
    const cli = resolve("packages/cli/dist/index.cjs");
    const config = join(dir, "palizade.yaml");
    const env = { ...process.env, HOME: dir, USERPROFILE: dir, CLAUDE_CONFIG_DIR: join(dir, ".claude"), PALIZADE_NO_DAEMON: "1" };
    const hook = (payload: object) => spawnSync(process.execPath, [cli, "-c", config, "hook", "claude-code"], {
      cwd: dir, env, input: JSON.stringify(payload), encoding: "utf8", timeout: 10000
    });
    expect(spawnSync(process.execPath, [cli, "init"], { cwd: dir, env, encoding: "utf8" }).status).toBe(0);
    await writeFile(config, `${await readFile(config, "utf8")}\nhooks: { failMode: closed, maxInputBytes: 1024 }\n`);
    const head = "https://head.example/report";
    const tail = "https://tail.example/report";
    const session = { session_id: "oversize-fixture", cwd: dir };
    const post = hook({
      ...session,
      tool_response: { content: [{ type: "text", text: `Start ${head}\n ${'café \\" '.repeat(1500)}\n ${tail} end` }] },
      hook_event_name: "PostToolUse",
      tool_name: "WebFetch",
      tool_input: { url: "https://source.example/report" }
    });
    expect(post.status, post.stderr).toBe(0);
    expect(post.stderr).toBe("");
    for (const url of [head, tail]) {
      const pre = hook({ ...session, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `curl ${url}` } });
      expect(JSON.parse(pre.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    }
    const pre = hook({
      ...session,
      tool_name: "Bash",
      tool_input: { command: "npm test".repeat(1000), hook_event_name: "PostToolUse" },
      hook_event_name: "PreToolUse"
    });
    expect(pre.status, pre.stderr).toBe(2);
    expect(JSON.parse(pre.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
