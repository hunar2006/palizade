#!/usr/bin/env node
// Lists tools from real MCP servers and reports how Palizade classifies them and whether the
// metadata checks flag any (false positives, since these are the official reference servers).
// usage: node eval/real-servers.mjs servers.yaml [--out results/real-servers.md] [--dump dir] [--timeout ms]
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { catalogEntryFor, classifyToolDetailed, collectToolsFromStdioServer, DEFAULT_METADATA_GUARD_CONFIG, InMemoryToolRegistry, parseConfig, reviewMetadata } from "../packages/core/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";

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
  let instructionLike = 0;
  for (const tool of tools) {
    const detection = await detector.detect(`${tool.title ?? ""}\n${tool.description ?? ""}`, { server: name, tool: tool.name, trust: server.trust, surface: "tool_description" });
    if (detection.score >= 0.55) { instructionLike += 1; flagged.push(`${name}/${tool.name}: description score ${detection.score.toFixed(2)} (${detection.labels.join(", ")})`); }
  }
  for (const item of review.items.filter((entry) => entry.flagged)) flagged.push(`${name}/${item.name}: ${item.detection.labels.join(", ")}`);
  rows.push({ name, catalog: catalogEntryFor(server)?.id ?? "-", tools: tools.length, ...classes, unknownNames: unknown, metadataFlags: review.items.filter((entry) => entry.flagged).length, instructionLike });
}

const lines = [
  "| Server | Catalog | Tools | Source | Sink | Pure | Unknown | Metadata flags | Instruction like |",
  "|---|---|---:|---:|---:|---:|---:|---:|---:|",
  ...rows.map((row) => row.error ? `| ${row.name} | error: ${row.error} | | | | | | | |` : `| ${row.name} | ${row.catalog} | ${row.tools} | ${row.source} | ${row.sink} | ${row.pure} | ${row.unknown} | ${row.metadataFlags} | ${row.instructionLike} |`)
];
const unknownList = rows.filter((row) => row.unknownNames?.length).map((row) => `- ${row.name}: ${row.unknownNames.join(", ")}`);
const text = [
  ...lines,
  "",
  unknownList.length ? `Unknown tools (blocked on untrusted servers until classified):\n${unknownList.join("\n")}` : "No unknown tools.",
  "",
  flagged.length ? `Flags:\n${flagged.map((line) => `- ${line}`).join("\n")}` : "No metadata or description flags."
].join("\n");
console.log(text);
if (values.out) await writeFile(values.out, `${text}\n`);
process.exit(0);
