#!/usr/bin/env node
// How well Palizade classifies tools of servers it does not know. Takes the real tool lists in the
// catalog test fixture, classifies each tool as if its server were not in the catalog (untrusted),
// and compares with the catalog's class. This is the development set for the name and schema
// rules; held out benchmarks (MCPTox, AgentDojo) are not used to tune them. Run `pnpm build` first.
// usage: node eval/classifier-devset.mjs [--names-only] [--list]
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { classifyToolDetailed, parseConfig } from "../packages/core/dist/index.js";

const { values } = parseArgs({ options: { "names-only": { type: "boolean", default: false }, list: { type: "boolean", default: false } } });
const fixture = JSON.parse(readFileSync(new URL("../packages/core/src/real-server-tools.fixture.json", import.meta.url), "utf8"));
const server = (command, args = []) => parseConfig(JSON.stringify({ servers: { s: { command, args, trust: "untrusted" } } })).servers.s;
const uncatalogued = server("uncatalogued-server");
const counts = new Map();
const unknown = [], unsafe = [];
let total = 0;
for (const [name, entry] of Object.entries(fixture)) {
  for (const tool of entry.tools) {
    total += 1;
    const truth = classifyToolDetailed(tool.name, server(entry.command, entry.args), tool).toolClass;
    const got = classifyToolDetailed(tool.name, uncatalogued, values["names-only"] ? undefined : tool).toolClass;
    counts.set(`${truth} -> ${got}`, (counts.get(`${truth} -> ${got}`) ?? 0) + 1);
    if (got === "unknown") unknown.push(`${name}/${tool.name}`);
    if (truth === "sink" && (got === "source" || got === "pure")) unsafe.push(`${name}/${tool.name}`);
  }
}
console.log(`Run on ${new Date().toISOString().slice(0, 10)}: \`node eval/classifier-devset.mjs${values["names-only"] ? " --names-only" : ""}\`, ${total} tools from ${Object.keys(fixture).length} servers, ${values["names-only"] ? "tool names only" : "full tool definitions"}`);
console.log(`unknown (blocked on untrusted servers): ${unknown.length}`);
console.log(`catalog sink classified as source or pure (unsafe): ${unsafe.length}`);
console.log(`catalog class -> class without catalog: ${[...counts].sort().map(([key, count]) => `${key}: ${count}`).join(", ")}`);
if (values.list) console.log(`unknown: ${unknown.join(", ")}\nunsafe: ${unsafe.join(", ")}`);
