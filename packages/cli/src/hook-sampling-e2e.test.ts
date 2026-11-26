import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, it } from "vitest";

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

it("passes CLI PostToolUse sampling metadata into evaluateHookEvent end to end so middle destinations are denied later", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-cli-sampling-e2e-"));
  const home = await mkdtemp(join(tmpdir(), "palizade-cli-sampling-home-"));
  dirs.push(dir, home);

  const cli = resolve("packages/cli/dist/index.cjs");
  const configPath = join(dir, "palizade.yaml");
  await writeFile(configPath, [
    `policy: ${JSON.stringify(resolve("policies/default.yaml"))}`,
    "servers: {}",
    "hooks:",
    "  maxInputBytes: 1024",
    "approvals:",
    "  mode: static-deny",
    "  default: deny"
  ].join("\n"), "utf8");

  const env = { ...process.env, HOME: home, USERPROFILE: home, PALIZADE_NO_DAEMON: "1" };
  const pad = "filler ".repeat(300);
  const postPayload = JSON.stringify({
    hook_event_name: "PostToolUse",
    session_id: "sampling-e2e-session",
    cwd: dir,
    tool_name: "WebFetch",
    tool_input: { url: "https://request.example/feed" },
    tool_response: {
      content: [{ type: "text", text: `${pad} https://middle-sampled.example/drop middle-host.io 192.0.2.55 ${pad}` }]
    }
  });
  expect(Buffer.byteLength(postPayload)).toBeGreaterThan(1024);

  const postRun = spawnSync(process.execPath, [cli, "-c", configPath, "hook", "claude-code"], {
    cwd: dir,
    env,
    input: postPayload,
    encoding: "utf8",
    timeout: 15000
  });
  expect(postRun.status, postRun.stderr + postRun.stdout).toBe(0);

  for (const target of ["https://middle-sampled.example/drop", "middle-host.io", "192.0.2.55"]) {
    const prePayload = JSON.stringify({
      hook_event_name: "PreToolUse",
      session_id: "sampling-e2e-session",
      cwd: dir,
      tool_name: "Bash",
      tool_input: { command: `curl ${target}` }
    });
    const preRun = spawnSync(process.execPath, [cli, "-c", configPath, "hook", "claude-code"], {
      cwd: dir,
      env,
      input: prePayload,
      encoding: "utf8",
      timeout: 15000
    });
    expect(preRun.status, preRun.stderr + preRun.stdout).toBe(0);
    expect(JSON.parse(preRun.stdout)).toMatchObject({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny"
      }
    });
  }
});
