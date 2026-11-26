import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterEach, expect, test } from "vitest";
import { StaticApprovalProvider } from "../../../packages/approvals/dist/index.js";
import { AuditLogger } from "../../../packages/audit/dist/index.js";
import { createDetector, InterceptionEngine, LockfileStore, parseConfig } from "../../../packages/core/dist/index.js";
import { parsePolicy } from "../../../packages/policy/dist/index.js";
import { InMemoryTaintStore } from "../../../packages/taint/dist/index.js";

const tools = ["read_file", "send_email", "delete_file", "create_file"].map((name) => ({ name, inputSchema: {} }));
const note = "A fictional cactus inventory for the fourth exhibition hall binder.";
let child;
let closed;

function connect(env = process.env, args = [join(import.meta.dirname, "bridge.mjs")]) {
  child = spawn(process.execPath, args, { env });
  child.stdin.setDefaultEncoding("utf8");
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  closed = new Promise((resolve) => child.once("close", resolve));
  return async (request) => {
    child.stdin.write(`${typeof request === "string" ? request : JSON.stringify(request)}\n`);
    const reply = await lines.next();
    if (reply.done) throw new Error(`Bridge exited early. ${stderr}`);
    return JSON.parse(reply.value);
  };
}

function connectWithPolicy(policy, preset = "default") {
  const source = `
    import { serve } from ${JSON.stringify(new URL("./bridge.mjs", import.meta.url).href)};
    import { parsePolicy } from ${JSON.stringify(new URL("../../../packages/policy/dist/index.js", import.meta.url).href)};
    await serve(new Map([[${JSON.stringify(preset)}, parsePolicy(${JSON.stringify(policy)})]]));`;
  return connect(process.env, ["--input-type=module", "--eval", source]);
}

afterEach(async () => {
  if (child) {
    child.stdin.end();
    expect(await closed).toBe(0);
    child = undefined;
  }
});

const start = (send, preset = "default", approvals = "deny") =>
  send({ op: "start", suite: "fixture", tools, prompt: "Read the report.", preset, approvals });
const check = (send, name, args = {}) => send({ op: "check", name, arguments: args });
const record = (send, callId, result) => send({ op: "record", callId, result, isError: false });

test("blocks a tainted outbound argument and clears the taint at the next episode", async () => {
  const send = connect();
  expect(await start(send)).toMatchObject({ ok: true, availableTools: tools.map(({ name }) => name) });
  const read = await check(send, "read_file", { path: "fixture.txt" });
  expect(read.decision).toBe("allow");
  expect(await record(send, read.callId, note)).toMatchObject({ ok: true, blocked: false, result: note });

  const args = { to: "receiver@example.invalid", body: note };
  expect(await check(send, "send_email", args)).toMatchObject({
    ok: true, decision: "block", ruleId: "block-tainted-sink", reason: expect.any(String)
  });
  expect(await send({ op: "end" })).toEqual({ ok: true, approvalPrompts: 0 });
  expect(await start(send)).toMatchObject({ ok: true });
  expect(await check(send, "send_email", args)).toMatchObject({ ok: true, decision: "allow", arguments: args });
});

test("denies and counts each approval prompt", async () => {
  const send = connect();
  expect(await start(send)).toMatchObject({ ok: true });
  const read = await check(send, "read_file", { path: "fixture.txt" });
  expect(await record(send, read.callId, note)).toMatchObject({ blocked: false });
  for (const path of ["sample-a.txt", "sample-b.txt"]) {
    expect(await check(send, "delete_file", { path })).toMatchObject({
      ok: true, decision: "needs_approval", ruleId: "approve-delete-after-untrusted",
      reason: expect.stringContaining("approval denied")
    });
  }
  expect(await send({ op: "end" })).toEqual({ ok: true, approvalPrompts: 2 });
});

test("allows a clean relative file write while still protecting explicit critical paths", async () => {
  const send = connect();
  await start(send);
  const write = await check(send, "create_file", { path: "fixture.txt", content: note });
  expect(write).toMatchObject({ decision: "allow", approvalPrompted: false });
  await record(send, write.callId, "Created.");
  expect(await check(send, "create_file", { path: ".palizade/fixture.txt", content: note })).toMatchObject({
    decision: "needs_approval", ruleId: "approve-critical-path"
  });
});

test.each([
  ["bridge", [join(import.meta.dirname, "bridge.mjs")]],
  ["scripted replay", [join(import.meta.dirname, "../replay.mjs"), "--traces", "missing.jsonl", "--out", "unused.jsonl"]]
])("the %s diagnoses a protected system temp folder", async (_, args) => {
  const protectedTemp = resolve(import.meta.dirname, "../../../.palizade/agentdojo-test-temp");
  await mkdir(protectedTemp, { recursive: true });
  const result = spawnSync(process.execPath, args, {
    env: { ...process.env, TEMP: protectedTemp, TMP: protectedTemp, TMPDIR: protectedTemp },
    input: "", encoding: "utf8"
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("The AgentDojo temp directory is under a Palizade protected path.");
});

test("reports the decision rule when blocking a copied destination starts quarantine", async () => {
  const send = connect();
  await start(send);
  const read = await check(send, "read_file");
  const address = "reader@example.invalid";
  await record(send, read.callId, `Fictional contact: ${address}.`);
  expect(await check(send, "send_email", { to: address, body: "Fixture text." })).toMatchObject({
    decision: "block", ruleId: "block-tainted-destination"
  });
});

test("rejects malformed requests and out of sequence results without losing the active episode", async () => {
  const send = connect();
  expect(await send("{bad json")).toEqual({ ok: false, error: "Malformed JSON." });
  expect(await send({ op: "start", suite: "fixture", tools: [null], prompt: "Read the report.", preset: "default" }))
    .toMatchObject({ ok: false });
  expect(await start(send)).toMatchObject({ ok: true });
  const read = await check(send, "read_file");
  expect(await record(send, read.callId + 1, note)).toMatchObject({ ok: false });
  expect(await check(send, "read_file")).toMatchObject({ ok: false });
  expect(await record(send, read.callId, note)).toMatchObject({ ok: true, blocked: false });
  expect(await record(send, read.callId, note)).toMatchObject({ ok: false });
});

test("forwards the policy transformed result", async () => {
  const send = connect();
  await start(send);
  const read = await check(send, "read_file");
  const result = await record(send, read.callId, `Fixture\u200b text\u200b.`);
  expect(result).toMatchObject({ ok: true, blocked: false, ruleId: "sanitize-suspicious-untrusted-output" });
  expect(result.result).toContain("<untrusted-content");
});

test("preapproves the strict catalog and still denies approval for a tool call", async () => {
  const send = connect();
  expect(await start(send, "strict")).toEqual({ ok: true, availableTools: tools.map(({ name }) => name) });
  expect(await check(send, "read_file")).toMatchObject({
    decision: "needs_approval", ruleId: null, reason: expect.stringContaining("policy default; approval denied")
  });
  expect(await send({ op: "end" })).toEqual({ ok: true, approvalPrompts: 2 });
});

test("denies a catalog approval required by a specific rule even with matching locks", async () => {
  const send = connectWithPolicy(`
version: 1
defaults: { action: require_approval, on_error: block }
rules:
  - id: confirm-approved-catalog
    when: { direction: response, method: tools/list, lock_status: approved }
    action: require_approval
    reason: policy default
`, "strict");
  expect(await start(send, "strict")).toEqual({ ok: true, availableTools: [] });
  expect(await check(send, "read_file")).toMatchObject({ decision: "block", ruleId: "confirm-approved-catalog" });
  expect(await send({ op: "end" })).toEqual({ ok: true, approvalPrompts: 1 });
});

test("returns the same redacted, unchanged or blocked result as the engine", async () => {
  const policy = `
version: 1
defaults: { action: allow, on_error: block }
rules:
  - id: withhold-result
    when: { direction: response, tool: send_email, method: tools/call }
    action: block
  - id: redact-result
    when: { direction: response, method: tools/call }
    action: redact_spans
`;
  const config = parseConfig(JSON.stringify({
    servers: { fixture: { command: "agentdojo", trust: "untrusted" } }
  }), join(tmpdir(), `palizade-engine-fixture-${randomUUID()}`));
  const engine = new InterceptionEngine({
    config, serverName: "fixture", server: config.servers.fixture, sessionId: "fixture",
    policy: parsePolicy(policy), detector: createDetector(config), taintStore: new InMemoryTaintStore(),
    audit: new AuditLogger([]), approvals: new StaticApprovalProvider(false, "fixture"), lockfile: new LockfileStore(config.lockfile)
  });
  const send = connectWithPolicy(policy);
  expect(await start(send)).toMatchObject({ ok: true });
  for (const [name, text, expected, ruleId] of [
    ["read_file", "Fixture\u200b text.", "Fixture[REDACTED:invisible-control-unicode] text.", "redact-result"],
    ["read_file", note, note, "redact-result"],
    ["send_email", "Fictional result.", null, "withhold-result"]
  ]) {
    const { callId } = await check(send, name);
    await engine.handleClientMessage({ jsonrpc: "2.0", id: callId, method: "tools/call", params: { name, arguments: {} } });
    const engineOutput = await engine.handleServerMessage({
      jsonrpc: "2.0", id: callId, result: { content: [{ type: "text", text }], isError: false }
    });
    const result = engineOutput.toClient[0]?.result?.content?.[0]?.text ?? null;
    expect(result).toBe(expected);
    expect(await record(send, callId, text)).toMatchObject({ ok: true, blocked: result === null, result, ruleId });
  }
});

test("uses product score fusion and keeps secret and PII detection opt in", async () => {
  const send = connectWithPolicy(`
version: 1
defaults: { action: allow, on_error: block }
rules:
  - id: redact-sensitive-result
    when: { direction: response, secret_detected: true, pii_detected: true }
    action: redact_secrets
  - id: redact-fused-result
    when: { direction: response, detector_score_gte: 0.31 }
    action: redact_spans
`);
  await start(send);
  const sensitive = await check(send, "read_file");
  const fixture = "Token: sk-FAKETESTSECRET00000000000000. Contact: reader@example.invalid.";
  expect(await record(send, sensitive.callId, fixture)).toMatchObject({ blocked: false, result: fixture, ruleId: null });
  const fused = await check(send, "read_file");
  expect(await record(send, fused.callId, `Fixture\u200b text.`)).toMatchObject({
    blocked: false, result: "Fixture[REDACTED:invisible-control-unicode] text.", ruleId: "redact-fused-result"
  });
});

test("creates no state files with fake API credentials in the environment", async () => {
  const bridgeFiles = async () => (await readdir(tmpdir())).filter((name) => name.startsWith("palizade-agentdojo-bridge-")).sort();
  const before = await bridgeFiles();
  const fakeKey = `fixture-key-${randomUUID()}`;
  const send = connect({ ...process.env, PALIZADE_EVAL_API_KEY: fakeKey, OPENAI_API_KEY: fakeKey });
  const replies = [await start(send)];
  replies.push(await check(send, "read_file"));
  replies.push(await record(send, replies.at(-1).callId, note), await send({ op: "end" }));
  expect(replies.every(({ ok }) => ok)).toBe(true);
  expect(JSON.stringify(replies)).not.toContain(fakeKey);
  child.stdin.end();
  expect(await closed).toBe(0);
  child = undefined;
  expect(await bridgeFiles()).toEqual(before);
});

test("grants approval prompts while keeping hard blocks blocked in default approved mode", async () => {
  const send = connect();
  expect(await start(send, "default", "approve")).toMatchObject({ ok: true, availableTools: tools.map(({ name }) => name) });
  const read = await check(send, "read_file", { path: "fixture.txt" });
  expect(read).toMatchObject({ ok: true, decision: "allow", approvalPrompted: false });
  expect(await record(send, read.callId, note)).toMatchObject({ ok: true, blocked: false, result: note });

  expect(await check(send, "send_email", { to: "receiver@example.invalid", body: note })).toMatchObject({
    ok: true, decision: "block", approvalPrompted: false, ruleId: "block-tainted-sink"
  });
  const del = await check(send, "delete_file", { path: "sample-a.txt" });
  expect(del).toMatchObject({
    ok: true, decision: "allow", approvalPrompted: true, ruleId: "approve-delete-after-untrusted",
    arguments: { path: "sample-a.txt" }
  });
  expect(await record(send, del.callId, "Removed.")).toMatchObject({ ok: true, blocked: false, result: "Removed." });
  expect(await send({ op: "end" })).toEqual({ ok: true, approvalPrompts: 1 });
});

test("grants default approval prompts and keeps hard blocks blocked in strict approved mode", async () => {
  const send = connect();
  expect(await start(send, "strict", "approve")).toEqual({ ok: true, availableTools: tools.map(({ name }) => name) });
  const read = await check(send, "read_file", { path: "fixture.txt" });
  expect(read).toMatchObject({ ok: true, decision: "allow", approvalPrompted: true });
  expect(await record(send, read.callId, note)).toMatchObject({ ok: true, blocked: false, result: note });
  expect(await check(send, "send_email", { to: "receiver@example.invalid", body: note })).toMatchObject({
    ok: true, decision: "block", approvalPrompted: false
  });
  const ended = await send({ op: "end" });
  expect(ended.ok).toBe(true);
  expect(ended.approvalPrompts).toBeGreaterThanOrEqual(2);

  expect(await send({ op: "start", suite: "fixture", tools, prompt: "Read.", preset: "default", approvals: "maybe" }))
    .toMatchObject({ ok: false });
});
