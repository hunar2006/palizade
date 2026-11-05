#!/usr/bin/env node
// Wall clock cost of one native hook call per client, the way the client runs it: a new process
// that reads the payload on stdin and prints a decision. Run `pnpm build` first.
// usage: node eval/hook-latency.mjs [--iterations 40] [--warmup 3] [--daemon] [--cli dist/index.cjs] [--out file.md]
import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { iterations: { type: "string", default: "40" }, warmup: { type: "string", default: "3" }, daemon: { type: "boolean", default: false }, cli: { type: "string" }, out: { type: "string" } } });
const cli = values.cli ? resolve(values.cli) : resolve(import.meta.dirname, "../packages/cli/dist/index.cjs");
const iterations = Number(values.iterations), warmup = Number(values.warmup);

const clients = {
  "claude-code": { args: ["hook", "claude-code"], payload: (cwd) => ({ hook_event_name: "PreToolUse", session_id: "bench", cwd, tool_name: "Bash", tool_input: { command: "ls -la" } }) },
  cursor: { args: ["hook", "cursor", "beforeShellExecution"], payload: (cwd) => ({ hook_event_name: "beforeShellExecution", conversation_id: "bench", cwd, command: "ls -la", sandbox: false }) },
  codex: { args: ["hook", "codex"], payload: (cwd) => ({ hook_event_name: "PreToolUse", session_id: "bench", cwd, tool_name: "Bash", tool_input: { command: "ls -la" } }) },
  gemini: { args: ["hook", "gemini", "BeforeTool"], payload: (cwd) => ({ hook_event_name: "BeforeTool", session_id: "bench", cwd, tool_name: "run_shell_command", tool_input: { command: "ls -la" } }) }
};

function run(args, input, cwd) {
  return new Promise((resolvePromise, reject) => {
    const start = performance.now();
    const child = spawn(process.execPath, args, { cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ ms: performance.now() - start, code, stdout }));
    child.stdin.end(input);
  });
}

const percentile = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
async function measure(args, input, cwd) {
  const samples = [];
  let last;
  for (let index = 0; index < warmup + iterations; index += 1) {
    last = await run(args, input, cwd);
    if (last.code !== 0) throw new Error(`exit ${last.code}: ${last.stdout}`);
    if (index >= warmup) samples.push(last.ms);
  }
  samples.sort((a, b) => a - b);
  return { p50: percentile(samples, 50), p95: percentile(samples, 95), last: last.stdout.trim() };
}

const dir = await mkdtemp(join(tmpdir(), "palizade-hook-latency-"));
const rows = [];
let daemon;
try {
  execFileSync(process.execPath, [cli, "init"], { cwd: dir, stdio: "ignore" });
  if (values.daemon) {
    daemon = spawn(process.execPath, [cli, "daemon"], { cwd: dir, stdio: ["ignore", "pipe", "inherit"] });
    await new Promise((ok, fail) => { daemon.stdout.once("data", ok); daemon.once("exit", (code) => fail(new Error(`daemon exited ${code}`))); });
  }
  const node = await measure(["-e", ""], "", dir);
  rows.push(["node -e \"\" (process start only)", node]);
  for (const [name, client] of Object.entries(clients)) rows.push([name, await measure([cli, ...client.args], JSON.stringify(client.payload(dir)), dir)]);
} finally {
  daemon?.kill();
  await rm(dir, { recursive: true, force: true });
}

const text = [
  `Run on ${new Date().toISOString().slice(0, 10)}: \`node eval/hook-latency.mjs --iterations ${iterations}${values.daemon ? " --daemon" : ""}${values.cli ? ` --cli ${values.cli}` : ""}\` (${process.platform}, Node ${process.versions.node}, ${values.daemon ? "daemon running" : "no daemon"})`,
  "",
  "| Client | p50 ms | p95 ms |",
  "|---|---:|---:|",
  ...rows.map(([name, row]) => `| ${name} | ${row.p50.toFixed(1)} | ${row.p95.toFixed(1)} |`)
].join("\n");
console.log(text);
if (values.out) await writeFile(values.out, `${text}\n`);
