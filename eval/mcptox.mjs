#!/usr/bin/env node
// Held out check of tool description poisoning against MCPTox (AAAI-26). The dataset has no
// license, so it is not copied here: clone https://github.com/zhiqiangwang4/MCPTox-Benchmark and
// pass its folder. Each poisoned tool is sent through a tools/list response with the default
// policy; the result is how many Palizade withholds, by paradigm and risk category.
// usage: node eval/mcptox.mjs <MCPTox-Benchmark folder> [--policy default] [--out results/mcptox.md]
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { InterceptionEngine, LockfileStore, parseConfig } from "../packages/core/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { InMemoryTaintStore } from "../packages/taint/dist/index.js";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { policy: { type: "string", default: "default" }, out: { type: "string" } } });
if (positionals.length !== 1) {
  console.error("usage: node eval/mcptox.mjs <MCPTox-Benchmark folder> [--policy default] [--out file.md]");
  process.exit(2);
}
const servers = JSON.parse(await readFile(join(positionals[0], "pure_tool.json"), "utf8"));
const items = servers.flatMap((server) => Object.values(server));
const policy = parsePolicy(await readFile(resolve(import.meta.dirname, `../policies/${values.policy}.yaml`), "utf8"));
const scratch = await mkdtemp(join(tmpdir(), "palizade-mcptox-"));

async function withheld(tool, index) {
  const name = `mcptox-${index}`;
  const config = parseConfig(JSON.stringify({ stateDir: scratch, policy: "unused", lockfile: join(scratch, `${name}.lock`), audit: { jsonl: join(scratch, "a.jsonl"), sqlite: join(scratch, "a.sqlite") }, taint: { sqlite: join(scratch, "t.sqlite"), keyPath: join(scratch, "t.key") }, servers: { [name]: { command: "x", trust: "untrusted" } } }), scratch);
  const engine = new InterceptionEngine({ config, serverName: name, server: config.servers[name], sessionId: "mcptox", policy, detector: new HeuristicDetector(), taintStore: new InMemoryTaintStore(), audit: new AuditLogger([{ write: async () => {} }]), approvals: { requestApproval: async () => ({ approved: false, reason: "eval", approver: "eval" }) }, lockfile: new LockfileStore(config.lockfile) });
  await engine.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const out = await engine.handleServerMessage({ jsonrpc: "2.0", id: 1, result: { tools: [tool] } });
  const listed = out.toClient[0]?.result?.tools ?? [];
  return !listed.some((entry) => entry.name === tool.name);
}

const tally = { all: [0, 0], paradigm: new Map(), risk: new Map() };
const add = (map, key, hit) => { const row = map.get(key) ?? [0, 0]; row[0] += hit ? 1 : 0; row[1] += 1; map.set(key, row); };
for (const [index, item] of items.entries()) {
  const hit = await withheld({ name: item.tool_name, description: item.tool_content, inputSchema: { type: "object", properties: {} } }, index);
  tally.all[0] += hit ? 1 : 0; tally.all[1] += 1;
  add(tally.paradigm, item.paradigm ?? "unknown", hit);
  add(tally.risk, item["security risk"] ?? "unknown", hit);
}
await rm(scratch, { recursive: true, force: true });
const pct = ([hit, total]) => `${hit}/${total} (${((100 * hit) / total).toFixed(1)}%)`;
const table = (title, map) => [`| ${title} | Withheld |`, "|---|---:|", ...[...map].sort(([a], [b]) => a.localeCompare(b)).map(([key, row]) => `| ${key} | ${pct(row)} |`)].join("\n");
const text = [
  `MCPTox poisoned tool descriptions withheld by the ${values.policy} policy, heuristic detector, server trust untrusted: ${pct(tally.all)}`,
  "",
  table("Paradigm", tally.paradigm),
  "",
  table("Risk category", tally.risk)
].join("\n");
console.log(text);
if (values.out) await writeFile(values.out, `${text}\n`);
