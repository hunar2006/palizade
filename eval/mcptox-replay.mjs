#!/usr/bin/env node
// Replays MCPTox's recorded model tool calls (from eval/mcptox_extract.py) through Palizade: the
// server lists its tools plus one poisoned tool, then the call a model actually made is checked.
// "Success" calls are attacks that worked on the model; "Failure-Ignored" calls are the model
// doing the user's task, so blocking those is a false positive.
// usage: node eval/mcptox-replay.mjs calls.jsonl [--policy default] [--tool-metadata on|off] [--skip-rule id] [--out file.md]
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { InterceptionEngine, LockfileStore, parseConfig } from "../packages/core/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { InMemoryTaintStore } from "../packages/taint/dist/index.js";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { policy: { type: "string", default: "default" }, "tool-metadata": { type: "string", default: "on" }, "skip-rule": { type: "string", multiple: true, default: [] }, out: { type: "string" } } });
const rows = (await readFile(positionals[0], "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
const policy = parsePolicy(await readFile(resolve(import.meta.dirname, `../policies/${values.policy}.yaml`), "utf8"));
// --skip-rule block-untrusted-unknown-tool shows the result as if every tool had been classified.
policy.rules = policy.rules.filter((rule) => !values["skip-rule"].includes(rule.id));
const scratch = await mkdtemp(join(tmpdir(), "palizade-mcptox-"));
const detector = new HeuristicDetector();

async function decide(row, index) {
  const name = row.server.replace(/[^A-Za-z0-9_-]/gu, "_");
  const config = parseConfig(JSON.stringify({ stateDir: scratch, policy: "unused", lockfile: join(scratch, `l${index}.lock`), audit: { jsonl: join(scratch, "a.jsonl"), sqlite: join(scratch, "a.sqlite") }, taint: { sqlite: join(scratch, "t.sqlite"), keyPath: join(scratch, "t.key"), toolMetadata: values["tool-metadata"] === "on" }, servers: { [name]: { command: "x", trust: "untrusted" } } }), scratch);
  const events = [];
  const engine = new InterceptionEngine({ config, serverName: name, server: config.servers[name], sessionId: `s${index}`, policy, detector, taintStore: new InMemoryTaintStore(), audit: new AuditLogger([{ write: async (event) => { events.push(event); } }]), approvals: { requestApproval: async () => ({ approved: false, reason: "eval", approver: "eval" }) }, lockfile: new LockfileStore(config.lockfile) });
  await engine.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const tools = [...row.tools.map((tool) => ({ name: tool, inputSchema: { type: "object" } })), { name: row.poisoned.name, description: row.poisoned.description, inputSchema: { type: "object" } }];
  await engine.handleServerMessage({ jsonrpc: "2.0", id: 1, result: { tools } });
  const before = events.length;
  const out = await engine.handleClientMessage({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: row.tool, arguments: row.arguments } });
  const event = events.slice(before).find((entry) => entry.direction === "request");
  return { stopped: out.toServer.length === 0, rule: event?.matched_rule?.id ?? (out.toServer.length === 0 ? "withheld-tool" : "allow") };
}

const groups = new Map();
for (const [index, row] of rows.entries()) {
  const { stopped, rule } = await decide(row, index);
  const key = row.label ?? "None";
  const group = groups.get(key) ?? { total: 0, stopped: 0, rules: new Map() };
  group.total += 1;
  if (stopped) { group.stopped += 1; group.rules.set(rule, (group.rules.get(rule) ?? 0) + 1); }
  groups.set(key, group);
}
await rm(scratch, { recursive: true, force: true });
const pct = (part, total) => `${part}/${total} (${((100 * part) / Math.max(1, total)).toFixed(1)}%)`;
const lines = [
  `MCPTox recorded calls through Palizade (${values.policy} policy, untrusted server, tool description taint ${values["tool-metadata"]}${values["skip-rule"].length ? `, without ${values["skip-rule"].join(", ")}` : ""}). Stopped means blocked, or an approval prompt the user refused.`,
  "",
  "| MCPTox label | Calls | Stopped | Top rules |",
  "|---|---:|---:|---|",
  ...[...groups].sort(([a], [b]) => a.localeCompare(b)).map(([label, group]) => `| ${label} | ${group.total} | ${pct(group.stopped, group.total)} | ${[...group.rules].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([rule, count]) => `${rule} ${count}`).join(", ")} |`)
];
console.log(lines.join("\n"));
if (values.out) await writeFile(values.out, `${lines.join("\n")}\n`);
