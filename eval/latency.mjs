#!/usr/bin/env node
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InterceptionEngine, LockfileStore } from "../packages/core/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { StaticApprovalProvider } from "../packages/approvals/dist/index.js";
import { InMemoryTaintStore } from "../packages/taint/dist/index.js";

const iterations = Number(process.argv[2] ?? 500);
const dir = await mkdtemp(join(tmpdir(), "palisade-latency-"));
const engine = makeEngine(dir);

await engine.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
await engine.handleServerMessage({
  jsonrpc: "2.0",
  id: 1,
  result: {
    tools: [
      { name: "echo", description: "Echo text.", inputSchema: {}, annotations: { readOnlyHint: true } },
      { name: "send_email", description: "Send email.", inputSchema: {}, annotations: { destructiveHint: true } }
    ]
  }
});

const samples = [];
for (let index = 0; index < iterations; index += 1) {
  const id = index + 10;
  const start = performance.now();
  await engine.handleClientMessage({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "echo", arguments: { text: `hello ${index}` } }
  });
  samples.push(performance.now() - start);
}

samples.sort((a, b) => a - b);
const p50 = percentile(samples, 0.5);
const p95 = percentile(samples, 0.95);
console.log(`latency iterations=${iterations} p50=${p50.toFixed(2)}ms p95=${p95.toFixed(2)}ms`);

await rm(dir, { recursive: true, force: true });

if (p95 > 50) {
  console.error("p95 latency exceeded 50ms budget");
  process.exitCode = 1;
}

function percentile(values, p) {
  return values[Math.min(values.length - 1, Math.floor(values.length * p))] ?? 0;
}

function makeEngine(dir) {
  const config = {
    stateDir: dir,
    policy: "unused",
    lockfile: join(dir, "palisade.lock"),
    audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false },
    approvals: { mode: "static-deny", timeoutMs: 10, default: "deny" },
    detectors: {
      heuristic: true,
      promptGuard2: { enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" }
    },
    transport: { maxMessageBytes: 67108864, maxBufferedBytes: 67108864, allowBatches: false, allowContentLength: false },
    taint: {
      sqlite: join(dir, "taint.sqlite"),
      keyPath: join(dir, "taint.key"),
      scope: "profile",
      profileId: "latency",
      ttlMs: 86400000,
      suspiciousScore: 0.35,
      fuzzyHammingMax: 7,
      temporal: { enabled: true, turns: 3, ttlMs: 300000, detectorScoreGte: 0.55 }
    },
    servers: {
      toy: {
        command: "node",
        args: [],
        cwd: process.cwd(),
        env: {},
        trust: "semi",
        toolClasses: { echo: "pure", send_email: "sink" },
        toolCapabilities: {},
        shell: false,
        allowShell: false
      }
    }
  };
  return new InterceptionEngine({
    config,
    serverName: "toy",
    server: config.servers.toy,
    sessionId: "latency-session",
    policy: parsePolicy("version: 1\ndefaults: { action: allow, on_error: block }\nrules: []\n"),
    detector: new HeuristicDetector(),
    taintStore: new InMemoryTaintStore(),
    audit: new AuditLogger([{ write: async () => {} }]),
    approvals: new StaticApprovalProvider(false, "bench"),
    lockfile: new LockfileStore(config.lockfile)
  });
}
