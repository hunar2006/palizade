import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { release } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { cli, createFixture, run } from "./fixture.mjs";

const { values } = parseArgs({ options: {
  iterations: { type: "string", default: "40" },
  warmup: { type: "string", default: "5" },
  out: { type: "string" }
} });
const iterations = Number(values.iterations);
const warmup = Number(values.warmup);
if (!Number.isInteger(iterations) || iterations < 30 || !Number.isInteger(warmup) || warmup < 1) {
  throw new Error("Use at least 30 iterations and at least one warmup run.");
}

const demo = await createFixture();
const rows = [];
try {
  const cwd = demo.setup("-Off");
  const { PALIZADE_NO_DAEMON, ...env } = demo.env;
  const input = JSON.stringify({
    session_id: "windows-hook-latency",
    cwd,
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "node --test label.test.cjs" },
    tool_use_id: "toolu_benchmark",
    permission_mode: "default"
  });
  const config = join(cwd, "palizade.yaml");
  const args = [cli, "-c", config, "hook", "claude-code"];

  function measure(name, args, input) {
    const samples = [];
    for (let index = 0; index < warmup + iterations; index++) {
      const start = performance.now();
      const result = run(process.execPath, args, { cwd, env, input });
      const ms = performance.now() - start;
      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.equal(result.stderr, "");
      assert.equal(result.stdout, "");
      if (index >= warmup) samples.push(ms);
    }
    samples.sort((left, right) => left - right);
    const percentile = (p) => samples[Math.ceil(p * samples.length) - 1];
    rows.push({ name, p50_ms: percentile(0.50), p95_ms: percentile(0.95) });
  }

  function checkRoute(daemon) {
    const result = run(process.execPath, args, { cwd, env: { ...env, NODE_DEBUG: "module" }, input });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /hook-client\.cjs/);
    assert.equal(/(?:[/\\])cli\.cjs"/.test(result.stderr), !daemon, "Unexpected hook route");
  }

  measure('Node spawn (node -e "")', ["-e", ""], "");
  measure("Trivial stdin hook", ["-e", "process.stdin.resume()"], input);
  checkRoute(false);
  measure("Palizade, no daemon", args, input);

  const daemon = spawn(process.execPath, [cli, "-c", config, "daemon"], {
    cwd, env, stdio: ["ignore", "pipe", "inherit"]
  });
  const exited = once(daemon, "close");
  try {
    const [ready] = await Promise.race([
      once(daemon.stdout, "data", { signal: AbortSignal.timeout(10_000) }),
      exited.then(([code]) => { throw new Error("Daemon exited before ready: " + code); })
    ]);
    assert.match(ready.toString(), /Palizade daemon .* listening on /);
    checkRoute(true);
    measure("Palizade, daemon running", args, input);
    checkRoute(true);
  } finally {
    daemon.kill();
    await exited;
  }

  const audit = (await readFile(join(cwd, ".palizade", "audit.jsonl"), "utf8")).trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(audit.length, 2 * (iterations + warmup) + 3);
  assert.ok(audit.every(({ action, tool }) => action === "allow" && tool === "Bash"));
} finally {
  await demo.close();
}

const result = { platform: process.platform, release: release(), arch: process.arch, node: process.version, iterations, warmup, rows };
console.log("Windows " + result.release + " " + result.arch + ", Node " + result.node +
  ", " + iterations + " runs per row after " + warmup + " warmups\n");
console.log("| Case | p50 (ms) | p95 (ms) |");
console.log("| --- | ---: | ---: |");
for (const row of rows) {
  console.log("| " + row.name + " | " + row.p50_ms.toFixed(1) + " | " + row.p95_ms.toFixed(1) + " |");
}
if (values.out) await writeFile(values.out, JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
