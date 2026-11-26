import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Command } from "commander";
import { evaluateHookEvent } from "@palizade/core";
import { afterAll, beforeAll, expect, it, vi } from "vitest";

vi.mock("@palizade/core", async (importOriginal) => ({
  ...await importOriginal<typeof import("@palizade/core")>(),
  evaluateHookEvent: vi.fn(async () => ({ exitCode: 0 }))
}));

let program: Command;
let home: string;
let configPath: string;

beforeAll(async () => {
  home = await mkdtemp(join(tmpdir(), "palizade-hook-input-"));
  configPath = join(home, "palizade.yaml");
  await writeFile(configPath, "hooks: { maxInputBytes: 1024 }\n");
  vi.stubEnv("HOME", home);
  vi.stubEnv("USERPROFILE", home);
  vi.stubEnv("CLAUDE_CONFIG_DIR", join(home, ".claude"));
  vi.stubEnv("CODEX_HOME", join(home, ".codex"));
  vi.stubGlobal("__PKG_VERSION__", "0.0.0");
  const parse = vi.spyOn(Command.prototype, "parseAsync").mockImplementationOnce(async function (this: Command) {
    program = this;
    return this;
  });
  try {
    await import("./index.js");
  } finally {
    parse.mockRestore();
  }
});

afterAll(async () => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  await rm(home, { recursive: true, force: true });
});

async function hook(client: string, chunks: Buffer[], ...args: string[]): Promise<void> {
  vi.mocked(evaluateHookEvent).mockClear();
  vi.stubGlobal("__palizadeHookStdin", { chunks, ended: true });
  const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
  const stdout = vi.spyOn(process.stdout, "write").mockReturnValue(true);
  const exitCode = process.exitCode;
  try {
    await program.parseAsync(["-c", configPath, "hook", client, ...args], { from: "user" });
  } finally {
    stderr.mockRestore();
    stdout.mockRestore();
    process.exitCode = exitCode;
  }
}

it("accepts a UTF-8 BOM at the start of a normal hook payload", async () => {
  const payload = { hook_event_name: "beforeShellExecution", conversation_id: "cursor-1", command: "npm test" };
  await hook("cursor", [Buffer.from(`\uFEFF${JSON.stringify(payload)}`)]);
  expect(evaluateHookEvent).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ payload }));
});

it("accepts repeated leading UTF-8 BOMs on a normal hook payload", async () => {
  const payload = { hook_event_name: "beforeShellExecution", conversation_id: "cursor-2bom", command: "npm test" };
  await hook("cursor", [Buffer.from(`\uFEFF\uFEFF${JSON.stringify(payload)}`)]);
  expect(evaluateHookEvent).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ payload }));
});

const post = {
  hook_event_name: "PostToolUse",
  session_id: "claude-1",
  tool_name: "WebFetch",
  url: "https://request.example/",
  tool_response: `${"x ".repeat(600)}https://middle.example/report, middle@example.org, plain.example and 192.0.2.1 and 2001:db8::1 ${"z ".repeat(600)}`
};

it("flags a sampled PostToolUse and keeps destinations from the discarded middle", async () => {
  const input = Buffer.from(JSON.stringify(post));
  const cut = input.indexOf("middle.example") + 4;
  await hook("claude-code", [input.subarray(0, cut), input.subarray(cut)]);
  expect(evaluateHookEvent).toHaveBeenCalledTimes(1);
  const call = vi.mocked(evaluateHookEvent).mock.calls[0]?.[0];
  expect(call?.payload).toMatchObject({ session_id: "claude-1" });
  expect(call?.payload).not.toHaveProperty("_palizadeSampled");
  expect(call?.payload).not.toHaveProperty("_palizadeSampledDestinations");
  expect(call?.sampling).toEqual({
    sampled: true,
    destinations: expect.arrayContaining([
      "url:https://middle.example/report", "email:middle@example.org", "host:plain.example", "host:192.0.2.1", "host:2001:db8::1"
    ])
  });
  expect(call?.sampling?.destinations).not.toContain("url:https://request.example/");
});

it("accepts a UTF-8 BOM split across chunks when sampling PostToolUse", async () => {
  const input = Buffer.from(`\uFEFF${JSON.stringify(post)}`);
  await hook("claude-code", [input.subarray(0, 1), input.subarray(1, 2), input.subarray(2)]);
  expect(evaluateHookEvent).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
    payload: expect.objectContaining({ session_id: "claude-1" }),
    sampling: expect.objectContaining({ sampled: true })
  }));
});

it("accepts repeated leading UTF-8 BOMs split across chunks when sampling PostToolUse", async () => {
  const input = Buffer.from(`\uFEFF\uFEFF${JSON.stringify(post)}`);
  await hook("claude-code", [input.subarray(0, 2), input.subarray(2, 4), input.subarray(4, 7), input.subarray(7)]);
  expect(evaluateHookEvent).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
    payload: expect.objectContaining({ session_id: "claude-1" }),
    sampling: expect.objectContaining({ sampled: true })
  }));
});

it.each(["claude-code", "cursor", "codex", "gemini"])("uses the %s prompt payload's session in place of --session", async (client) => {
  const { prompt } = JSON.parse(readFileSync(resolve(`packages/cli/test/hook-payloads/${client}.json`), "utf8"));
  await hook(client, [Buffer.from(JSON.stringify(prompt))], "--session", "cli-session");
  expect(evaluateHookEvent).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ client, event: prompt.hook_event_name, payload: prompt }));
  expect(vi.mocked(evaluateHookEvent).mock.calls[0]?.[0]).not.toHaveProperty("sessionId");
});

it("skips prompt recording when stdin has no session id", async () => {
  await hook("cursor", [Buffer.from('{"hook_event_name":"beforeSubmitPrompt","prompt":"Run the tests"}')], "--session", "cli-session");
  expect(evaluateHookEvent).not.toHaveBeenCalled();
});
