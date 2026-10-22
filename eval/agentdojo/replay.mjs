#!/usr/bin/env node
// Replays AgentDojo ground truth traces (from export_traces.py) through Palizade and writes
// one decision per tool call: allow, approval (Palizade asked the user), or block.
import { createReadStream } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { InterceptionEngine, LockfileStore, parseConfig } from "../../packages/core/dist/index.js";
import { AuditLogger } from "../../packages/audit/dist/index.js";
import { HeuristicDetector } from "../../packages/detectors/dist/index.js";
import { parsePolicy } from "../../packages/policy/dist/index.js";
import { InMemoryTaintStore, extractStatedObservables } from "../../packages/taint/dist/index.js";

const ROOT = resolve(import.meta.dirname, "../..");
const { values } = parseArgs({
  options: {
    traces: { type: "string" },
    out: { type: "string" },
    policy: { type: "string", default: "default" },
    trust: { type: "string", default: "untrusted" },
    // "on" feeds the user task prompt to Palizade, as the prompt hooks do in Claude Code, Codex and Cursor.
    "user-intent": { type: "string", default: "on" }
  }
});
if (!values.traces || !values.out) {
  console.error("usage: replay.mjs --traces traces.jsonl --out decisions.jsonl [--policy default] [--trust untrusted]");
  process.exit(2);
}

const policy = parsePolicy(await readFile(join(ROOT, "policies", `${values.policy}.yaml`), "utf8"));
const tools = new Map();
const results = [];
const lines = createInterface({ input: createReadStream(values.traces, "utf8"), crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  const record = JSON.parse(line);
  if (record.kind === "tools") {
    tools.set(record.suite, record.tools);
    continue;
  }
  results.push(await replayTrace(record, tools.get(record.suite)));
}
await writeFile(values.out, results.map((result) => JSON.stringify(result)).join("\n") + "\n");
console.error(`replayed ${results.length} traces with policy=${values.policy} trust=${values.trust} user-intent=${values["user-intent"]}`);

async function replayTrace(trace, suiteTools) {
  const dir = await mkdtemp(join(tmpdir(), "palizade-agentdojo-"));
  try {
    const serverName = trace.suite;
    const config = parseConfig(JSON.stringify({
      stateDir: dir,
      policy: "unused",
      lockfile: join(dir, "palizade.lock"),
      audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite") },
      taint: { sqlite: join(dir, "taint.sqlite"), keyPath: join(dir, "taint.key") },
      servers: { [serverName]: { command: "agentdojo", trust: values.trust } }
    }), dir);
    let current;
    const events = [];
    const taintStore = new InMemoryTaintStore();
    const sessionId = `${trace.suite}-${trace.user_task}-${trace.injection_task ?? "clean"}`;
    if (values["user-intent"] === "on" && typeof trace.prompt === "string") {
      taintStore.addUserStatements(sessionId, extractStatedObservables(trace.prompt), 3_600_000);
    }
    const engine = new InterceptionEngine({
      config,
      serverName,
      server: config.servers[serverName],
      sessionId,
      policy,
      detector: new HeuristicDetector(),
      taintStore,
      audit: new AuditLogger([{ write: async (event) => { events.push(event); } }]),
      // Approve so the scripted trace continues; the decision is recorded as "approval".
      approvals: { requestApproval: async () => { if (current) current.outcome = "approval"; return { approved: true, reason: "replay", approver: "replay" }; } },
      lockfile: new LockfileStore(config.lockfile)
    });
    await engine.handleClientMessage({ jsonrpc: "2.0", id: 0, method: "tools/list", params: {} });
    await engine.handleServerMessage({ jsonrpc: "2.0", id: 0, result: { tools: suiteTools } });

    const decisions = [];
    let id = 1;
    for (const call of trace.calls) {
      current = { phase: call.phase, function: call.function, outcome: "allow" };
      const before = events.length;
      const request = await engine.handleClientMessage({ jsonrpc: "2.0", id, method: "tools/call", params: { name: call.function, arguments: call.args } });
      const ruleEvent = events.slice(before).find((event) => event.direction === "request" && event.method === "tools/call");
      current.rule = ruleEvent?.matched_rule?.id;
      current.toolClass = ruleEvent?.metadata?.toolClass;
      if (request.toServer.length === 0) {
        current.outcome = "block";
      } else {
        await engine.handleServerMessage({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: String(call.output ?? "") }] } });
      }
      decisions.push(current);
      id += 1;
    }
    return { suite: trace.suite, user_task: trace.user_task, injection_task: trace.injection_task, decisions };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
