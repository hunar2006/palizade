// Contract tests: each client's sample payloads through the real `palizade hook` command, checking
// the exact JSON and exit code Palizade returns for allow, deny, ask and errors. Sources of the
// samples are in test/hook-payloads/<client>.json.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const cli = resolve("packages/cli/dist/index.cjs");
type Client = "claude-code" | "codex" | "cursor" | "gemini";
const events: Record<Client, { pre: string; post: string; prompt: string }> = {
  "claude-code": { pre: "PreToolUse", post: "PostToolUse", prompt: "UserPromptSubmit" },
  codex: { pre: "PreToolUse", post: "PostToolUse", prompt: "UserPromptSubmit" },
  cursor: { pre: "beforeShellExecution", post: "afterShellExecution", prompt: "beforeSubmitPrompt" },
  gemini: { pre: "BeforeTool", post: "AfterTool", prompt: "BeforeAgent" }
};
const failed = "Hook evaluation failed; check the local configuration and input.";
const askReason = "Contract ask.; approval denied (native hooks defer approval decisions to the client)";
const cannotAsk = (client: string) => `Palizade needs your approval for this call, and ${client} hooks cannot ask; run it yourself if you approve. ${askReason}`;
const preToolUse = (decision: string, reason: string) => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } });
const cursorDecision = (permission: string, reason: string) => ({ permission, user_message: reason, agent_message: reason });

// What each client must receive. undefined means no output (the client's normal flow continues).
const expected: Record<Client, { deny: object; ask: object; error: object; prompt?: object }> = {
  "claude-code": { deny: preToolUse("deny", "Contract deny."), ask: preToolUse("ask", askReason), error: preToolUse("deny", failed) },
  // Codex runs the tool when a hook answers ask, and Gemini CLI has no ask, so both get a deny.
  codex: { deny: preToolUse("deny", "Contract deny."), ask: preToolUse("deny", cannotAsk("Codex")), error: preToolUse("deny", failed) },
  cursor: { deny: cursorDecision("deny", "Contract deny."), ask: cursorDecision("ask", askReason), error: cursorDecision("deny", failed), prompt: { continue: true } },
  gemini: { deny: { decision: "deny", reason: "Contract deny." }, ask: { decision: "deny", reason: cannotAsk("Gemini CLI") }, error: { decision: "deny", reason: failed } }
};

describe.each(Object.keys(events) as Client[])("%s hook contract", (client) => {
  const samples = JSON.parse(readFileSync(resolve(`packages/cli/test/hook-payloads/${client}.json`), "utf8")) as { pre: Record<string, unknown>; post: object; prompt: object };
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "palizade-contract-"));
    await writeFile(join(dir, "palizade.yaml"), "servers: {}\npolicy: contract-policy.yaml\nstateDir: .palizade\n");
    await writeFile(join(dir, "contract-policy.yaml"), [
      "version: 1",
      "defaults: { action: allow, on_error: block }",
      "rules:",
      "  - { id: contract-deny, when: { direction: request, argument_regex: DENY_ME }, action: block, reason: Contract deny. }",
      "  - { id: contract-ask, when: { direction: request, argument_regex: ASK_ME }, action: require_approval, reason: Contract ask. }",
      ""
    ].join("\n"));
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const hook = (event: string, input: string) => {
    const run = spawnSync(process.execPath, [cli, "-c", join(dir, "palizade.yaml"), "hook", client, event], { cwd: dir, input, encoding: "utf8", timeout: 20000, env: { ...process.env, PALIZADE_NO_DAEMON: "1" } });
    return { status: run.status, output: run.stdout.trim() ? JSON.parse(run.stdout) as unknown : undefined };
  };
  const withCommand = (command: string) => {
    const payload = structuredClone(samples.pre);
    if (typeof payload.command === "string") payload.command = command;
    else (payload.tool_input as Record<string, unknown>).command = command;
    return JSON.stringify(payload);
  };

  it("allows with no output", () => expect(hook(events[client].pre, withCommand("npm test"))).toEqual({ status: 0, output: undefined }));
  it("denies in the client's format", () => expect(hook(events[client].pre, withCommand("echo DENY_ME"))).toEqual({ status: 0, output: expected[client].deny }));
  it("asks, or denies where the client cannot ask", () => expect(hook(events[client].pre, withCommand("echo ASK_ME"))).toEqual({ status: 0, output: expected[client].ask }));
  it("fails closed on invalid input with exit 2", () => expect(hook(events[client].pre, "{not json")).toEqual({ status: 2, output: expected[client].error }));
  it("accepts the post tool sample without a decision", () => expect(hook(events[client].post, JSON.stringify(samples.post))).toEqual({ status: 0, output: undefined }));
  it("never blocks the prompt, even on invalid input", () => {
    expect(hook(events[client].prompt, JSON.stringify(samples.prompt))).toEqual({ status: 0, output: expected[client].prompt });
    expect(hook(events[client].prompt, "{not json")).toEqual({ status: 0, output: expected[client].prompt });
  });
});
