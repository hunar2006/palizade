#!/usr/bin/env node
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InterceptionEngine, LockfileStore } from "../packages/core/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { StaticApprovalProvider } from "../packages/approvals/dist/index.js";
import { InMemoryTaintStore, SqliteTaintStore } from "../packages/taint/dist/index.js";

const iterations = Number(process.argv[2] ?? 500);
const dir = await mkdtemp(join(tmpdir(), "palizade-latency-"));
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

// Store-level cost on the default SQLite store: fingerprint a 4 KB page in, then check a
// sink argument against every stored record (no match, so the full scan runs).
const store = new SqliteTaintStore(join(dir, "bench-taint.sqlite"), { keyPath: join(dir, "bench.key") });
const page = (i) => `Page ${i}. ${"Quarterly vendor report with ordinary prose and reconciled totals. ".repeat(60)}`;
const ingest = [];
for (let i = 0; i < 200; i += 1) {
  const start = performance.now();
  store.add({ sessionId: "bench", sourceServer: "fetch", sourceTool: "fetch_url", trust: "untrusted", text: page(i), detectorScore: 0, labels: [] });
  ingest.push(performance.now() - start);
}
const sinkArg = "Hi team, summary attached. Totals reconcile and nothing needs action this week. ".repeat(4);
const check = [];
for (let i = 0; i < 200; i += 1) {
  const start = performance.now();
  store.match("bench", sinkArg);
  check.push(performance.now() - start);
}
store.close();
for (const [label, values] of [["ingest 4KB page", ingest], [`sink check vs ${ingest.length} records`, check]]) {
  values.sort((a, b) => a - b);
  console.log(`sqlite ${label}: p50=${percentile(values, 0.5).toFixed(2)}ms p95=${percentile(values, 0.95).toFixed(2)}ms`);
}

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
    lockfile: join(dir, "palizade.lock"),
    audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false, errorVerbosity: true },
    approvals: { mode: "static-deny", timeoutMs: 10, default: "deny" },
    detectors: {
      heuristic: true,
      promptGuard2: { enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" },
      secrets: { enabled: false, aws: true, generic: true, jwt: true, privateKey: true, googleApiKey: true, stripe: true, slack: true, github: true, openai: true },
      pii: { enabled: false, email: true, ssn: true, creditCard: true, phone: true }
    },
    egress: { allowlist: { hosts: [], emails: [] } },
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
        sensitive: false,
        sensitiveTools: {},
        sensitivePathPatterns: [],
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
