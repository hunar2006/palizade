#!/usr/bin/env node
// Lists tools from real MCP servers and reports how Palizade classifies them, and how many tools
// the default policy would withhold when the list passes through Palizade (false positives, since
// these are published servers).
// usage: node eval/real-servers.mjs servers.yaml [--out results/real-servers.md] [--dump dir] [--timeout ms]
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { catalogEntryFor, classifyToolDetailed, collectToolsFromStdioServer, DEFAULT_METADATA_GUARD_CONFIG, InMemoryToolRegistry, InterceptionEngine, LockfileStore, parseConfig, reviewMetadata } from "../packages/core/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { InMemoryTaintStore } from "../packages/taint/dist/index.js";

const defaultPolicy = parsePolicy(await readFile(resolve(import.meta.dirname, "../policies/default.yaml"), "utf8"));
const scratch = await mkdtemp(join(tmpdir(), "palizade-real-"));

/** Sends the tool list through an engine with the default policy and returns the tools it withholds. */
async function withheldByDefaultPolicy(name, server, tools) {
  const config = parseConfig(JSON.stringify({ stateDir: scratch, policy: "unused", lockfile: join(scratch, `${name}.lock`), audit: { jsonl: join(scratch, "audit.jsonl"), sqlite: join(scratch, "audit.sqlite") }, taint: { sqlite: join(scratch, "taint.sqlite"), keyPath: join(scratch, "taint.key") }, servers: { [name]: { command: server.command ?? "x", args: server.args ?? [], trust: server.trust } } }), scratch);
  const engine = new InterceptionEngine({ config, serverName: name, server: config.servers[name], sessionId: "real", policy: defaultPolicy, detector: new HeuristicDetector(), taintStore: new InMemoryTaintStore(), audit: new AuditLogger([{ write: async () => {} }]), approvals: { requestApproval: async () => ({ approved: false, reason: "eval", approver: "eval" }) }, lockfile: new LockfileStore(config.lockfile) });
  await engine.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const out = await engine.handleServerMessage({ jsonrpc: "2.0", id: 1, result: { tools } });
  const listed = new Set((out.toClient[0]?.result?.tools ?? []).map((tool) => tool.name));
  return tools.map((tool) => tool.name).filter((tool) => !listed.has(tool));
}

const { values, positionals } = parseArgs({ allowPositionals: true, options: { out: { type: "string" }, dump: { type: "string" }, timeout: { type: "string", default: "20000" } } });
if (positionals.length !== 1) {
  console.error("usage: node eval/real-servers.mjs servers.yaml [--out file.md]");
  process.exit(2);
}
const config = parseConfig(await readFile(positionals[0], "utf8"));
const detector = new HeuristicDetector();
const registry = new InMemoryToolRegistry();
const names = Object.keys(config.servers);
const rows = [];
const flagged = [];
for (const [name, server] of Object.entries(config.servers)) {
  let tools;
  try {
    tools = await collectToolsFromStdioServer(server, Number(values.timeout), { serverName: name });
    if (values.dump) { await mkdir(values.dump, { recursive: true }); await writeFile(join(values.dump, `${name}.json`), JSON.stringify(tools, null, 2)); }
  } catch (error) {
    rows.push({ name, error: String(error?.message ?? error).slice(0, 120) });
    continue;
  }
  const classes = { source: 0, sink: 0, pure: 0, unknown: 0 };
  const unknown = [];
  for (const tool of tools) {
    const result = classifyToolDetailed(tool.name, server, tool);
    classes[result.toolClass] += 1;
    if (result.toolClass === "unknown") unknown.push(tool.name);
  }
  const review = await reviewMetadata(tools.map((tool) => ({ name: tool.name, value: tool })), {
    serverName: name, configuredServers: names, registry, config: DEFAULT_METADATA_GUARD_CONFIG, tools: true,
    detect: (text) => detector.detect(text, { server: name, trust: server.trust, surface: "tool_description" })
  });
  for (const item of review.items.filter((entry) => entry.flagged)) flagged.push(`${name}/${item.name}: ${item.detection.labels.join(", ")}`);
  const withheld = await withheldByDefaultPolicy(name, server, tools);
  for (const tool of withheld) flagged.push(`${name}/${tool}: withheld by the default policy`);
  rows.push({ name, catalog: catalogEntryFor(server)?.id ?? "-", tools: tools.length, ...classes, unknownNames: unknown, metadataFlags: review.items.filter((entry) => entry.flagged).length, withheld: withheld.length });
}

const lines = [
  "| Server | Catalog | Tools | Source | Sink | Pure | Unknown | Metadata flags | Withheld |",
  "|---|---|---:|---:|---:|---:|---:|---:|---:|",
  ...rows.map((row) => row.error ? `| ${row.name} | error: ${row.error} | | | | | | | |` : `| ${row.name} | ${row.catalog} | ${row.tools} | ${row.source} | ${row.sink} | ${row.pure} | ${row.unknown} | ${row.metadataFlags} | ${row.withheld} |`)
];
const unknownList = rows.filter((row) => row.unknownNames?.length).map((row) => `- ${row.name}: ${row.unknownNames.join(", ")}`);
const text = [
  ...lines,
  "",
  unknownList.length ? `Unknown tools (blocked on untrusted servers until classified):\n${unknownList.join("\n")}` : "No unknown tools.",
  "",
  flagged.length ? `Flags:\n${flagged.map((line) => `- ${line}`).join("\n")}` : "No metadata flags and no tools withheld."
].join("\n");
console.log(text);
if (values.out) await writeFile(values.out, `${text}\n`);
await rm(scratch, { recursive: true, force: true });
process.exit(0);
