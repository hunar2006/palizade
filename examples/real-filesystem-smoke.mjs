#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ListRootsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const cwd = process.cwd();
const smokeDir = join(cwd, ".palizade", "smoke");
const largeFile = join(smokeDir, "large.txt");
await mkdir(smokeDir, { recursive: true });
await writeFile(largeFile, `${"large-payload-line\n".repeat(16_384)}`, "utf8");

const client = new Client(
  { name: "palizade-real-filesystem-smoke", version: "0.1.0" },
  { capabilities: { roots: { listChanged: true }, sampling: {} } }
);
client.setRequestHandler(ListRootsRequestSchema, async () => ({
  roots: [{ uri: `file://${cwd}`, name: "MCProtect workspace" }]
}));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["packages/cli/dist/index.cjs", "wrap", "filesystem"],
  cwd,
  stderr: "pipe"
});

transport.stderr?.on("data", (chunk) => {
  const text = String(chunk);
  if (!text.includes("ExperimentalWarning")) {
    process.stderr.write(text);
  }
});

await client.connect(transport);
await client.ping();
await client.sendRootsListChanged();

const tools = await client.listTools();
const names = new Set(tools.tools.map((tool) => tool.name));
for (const required of ["read_text_file", "write_file", "list_directory"]) {
  if (!names.has(required)) {
    throw new Error(`Filesystem smoke missing tool: ${required}`);
  }
}

const readme = await client.callTool({
  name: "read_text_file",
  arguments: { path: resolve(cwd, "README.md") }
});
const large = await client.callTool({
  name: "read_text_file",
  arguments: { path: largeFile }
});

console.log(`filesystem tools: ${tools.tools.length}`);
console.log(`README content blocks: ${Array.isArray(readme.content) ? readme.content.length : 0}`);
console.log(`large payload bytes: ${JSON.stringify(large).length}`);
console.log("real filesystem smoke: ok");

await transport.close();
