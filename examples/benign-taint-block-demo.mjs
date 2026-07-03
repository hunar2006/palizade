#!/usr/bin/env node
// Demonstrates provenance-only blocking: this does not depend on detecting malicious text.
// Untrusted or source-provenance data flowing into a sink is sufficient to stop silent exfiltration.
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticApprovalProvider } from "../packages/approvals/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { InterceptionEngine, LockfileStore } from "../packages/core/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { SqliteTaintStore } from "../packages/taint/dist/index.js";

const policy = parsePolicy(`version: 1
defaults:
  action: allow
  on_error: block
rules:
  - id: block-tainted-sink
    when: { direction: request, method: tools/call, tool_class: sink, taint: true }
    action: block
    reason: Tainted source content cannot be written to a sink.
`);

const benignContent = "Quarterly revenue figures for internal planning. Q1 ARR 1250000. Renewal forecast 94 percent.";
const demoDir = await mkdtemp(join(tmpdir(), "palizade-benign-taint-demo-"));
const outputFile = join(demoDir, "leaked-report.txt");
const events = [];
const config = makeConfig(demoDir);
const readStore = new SqliteTaintStore(config.taint.sqlite, {
  scope: config.taint.scope,
  profileId: config.taint.profileId,
  keyPath: config.taint.keyPath,
  ttlMs: config.taint.ttlMs
});
const writeStore = new SqliteTaintStore(config.taint.sqlite, {
  scope: config.taint.scope,
  profileId: config.taint.profileId,
  keyPath: config.taint.keyPath,
  ttlMs: config.taint.ttlMs
});

try {
  const reader = makeEngine({
    config,
    serverName: "reader",
    server: config.servers.reader,
    sessionId: "read-session",
    taintStore: readStore,
    events
  });
  const writer = makeEngine({
    config,
    serverName: "writer",
    server: config.servers.writer,
    sessionId: "write-session",
    taintStore: writeStore,
    events
  });

  await primeTools(reader, "read_file", "Read a file.", true);
  await primeTools(writer, "write_file", "Write a file.", false);

  await reader.handleClientMessage({
    jsonrpc: "2.0",
    id: 10,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: join(demoDir, "revenue.txt") } }
  });
  await reader.handleServerMessage({
    jsonrpc: "2.0",
    id: 10,
    result: {
      content: [{
        type: "text",
        text: benignContent
      }]
    }
  });

  const blocked = await writer.handleClientMessage({
    jsonrpc: "2.0",
    id: 20,
    method: "tools/call",
    params: {
      name: "write_file",
      arguments: {
        path: outputFile,
        content: benignContent
      }
    }
  });

  const blockEvent = events.find((event) => event.server === "writer" && event.action === "block");
  const readEvent = events.find((event) => event.server === "reader" && event.method === "tools/call" && event.direction === "response");
  const outputExists = await exists(outputFile);
  const blockedByProxy = blocked.toServer.length === 0 && "error" in blocked.toClient[0];
  const pass = Boolean(blockEvent) && blockedByProxy && !outputExists;

  console.log("Palizade benign provenance block demo");
  console.log(`read_detector_score=${readEvent?.detector.score ?? "-"}`);
  console.log(`write_blocked=${blockedByProxy}`);
  console.log(`block_rule=${blockEvent?.matched_rule?.id ?? "-"}`);
  console.log(`block_message=${blocked.toClient[0]?.error?.message ?? "-"}`);
  console.log(`output_created=${outputExists}`);
  console.log(`PASS=${pass}`);

  if (!pass) {
    process.exitCode = 1;
  }
} finally {
  readStore.close();
  writeStore.close();
  await rm(demoDir, { recursive: true, force: true });
}

function makeEngine({ config, serverName, server, sessionId, taintStore, events }) {
  return new InterceptionEngine({
    config,
    serverName,
    server,
    sessionId,
    policy,
    detector: new HeuristicDetector(),
    taintStore,
    audit: new AuditLogger([{ write: async (event) => { events.push(event); } }]),
    approvals: new StaticApprovalProvider(false, "demo denies approvals"),
    lockfile: new LockfileStore(config.lockfile)
  });
}

async function primeTools(engine, name, description, readOnly) {
  await engine.handleClientMessage({ jsonrpc: "2.0", id: `${name}-list`, method: "tools/list", params: {} });
  await engine.handleServerMessage({
    jsonrpc: "2.0",
    id: `${name}-list`,
    result: {
      tools: [{
        name,
        description,
        inputSchema: {},
        annotations: readOnly ? { readOnlyHint: true } : { destructiveHint: true }
      }]
    }
  });
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function makeConfig(dir) {
  return {
    stateDir: dir,
    policy: "unused",
    lockfile: join(dir, "palizade.lock"),
    audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false },
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
      profileId: "benign-provenance-demo",
      ttlMs: 86400000,
      suspiciousScore: 0.35,
      fuzzyHammingMax: 7,
      temporal: { enabled: true, turns: 3, ttlMs: 300000, detectorScoreGte: 0.55 }
    },
    servers: {
      reader: {
        command: "filesystem-reader",
        args: [],
        cwd: process.cwd(),
        env: {},
        trust: "semi",
        toolClasses: { read_file: "source" },
        toolCapabilities: { read_file: ["reads_sensitive_data"] },
        sensitive: false,
        sensitiveTools: {},
        sensitivePathPatterns: [],
        shell: false,
        allowShell: false
      },
      writer: {
        command: "filesystem-writer",
        args: [],
        cwd: process.cwd(),
        env: {},
        trust: "semi",
        toolClasses: { write_file: "sink" },
        toolCapabilities: { write_file: ["writes_local"] },
        sensitive: false,
        sensitiveTools: {},
        sensitivePathPatterns: [],
        shell: false,
        allowShell: false
      }
    }
  };
}
