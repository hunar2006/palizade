#!/usr/bin/env node
// Demonstrates redact_secrets: PII detected in outbound message args is stripped
// and the egress call is allowed to continue with redacted payload.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticApprovalProvider } from "../packages/approvals/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { InterceptionEngine, LockfileStore } from "../packages/core/dist/index.js";
import { DetectorPipeline, SensitiveDataDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { InMemoryTaintStore } from "../packages/taint/dist/index.js";

const policy = parsePolicy(`version: 1
defaults:
  action: allow
  on_error: block
rules:
  - id: redact-pii-egress
    when:
      direction: request
      method: tools/call
      pii_detected: true
      capabilities_any: [sends_message]
    action: redact_secrets
    reason: PII-like content should be redacted before egress.
`);

const demoDir = await mkdtemp(join(tmpdir(), "palizade-pii-redact-demo-"));
const events = [];
const config = makeConfig(demoDir);

try {
  const engine = new InterceptionEngine({
    config,
    serverName: "mail",
    server: config.servers.mail,
    sessionId: "pii-demo-session",
    policy,
    detector: new DetectorPipeline([
      new SensitiveDataDetector({ pii: { enabled: true } })
    ]),
    taintStore: new InMemoryTaintStore(),
    audit: new AuditLogger([{ write: async (event) => { events.push(event); } }]),
    approvals: new StaticApprovalProvider(false, "demo denies approvals"),
    lockfile: new LockfileStore(config.lockfile)
  });

  await primeTools(engine);
  const forwarded = await engine.handleClientMessage({
    jsonrpc: "2.0",
    id: 10,
    method: "tools/call",
    params: {
      name: "send_email",
      arguments: {
        to: "ops",
        subject: "customer followup",
        body: "Customer SSN 123-45-6789 and email jane@example.test need review."
      }
    }
  });

  const forwardedJson = JSON.stringify(forwarded.toServer[0]);
  const pass = forwarded.toServer.length === 1 &&
    !forwardedJson.includes("123-45-6789") &&
    !forwardedJson.includes("jane@example.test") &&
    forwardedJson.includes("[REDACTED:pii:ssn]") &&
    forwardedJson.includes("[REDACTED:pii:email]");

  console.log("Palizade PII redact demo");
  console.log(`call_forwarded=${forwarded.toServer.length === 1}`);
  console.log(`redacted_ssn=${!forwardedJson.includes("123-45-6789")}`);
  console.log(`redacted_email=${!forwardedJson.includes("jane@example.test")}`);
  console.log(`forwarded_payload=${forwardedJson}`);
  console.log(`PASS=${pass}`);

  if (!pass) {
    process.exitCode = 1;
  }
} finally {
  await rm(demoDir, { recursive: true, force: true });
}

async function primeTools(engine) {
  await engine.handleClientMessage({ jsonrpc: "2.0", id: "tools", method: "tools/list", params: {} });
  await engine.handleServerMessage({
    jsonrpc: "2.0",
    id: "tools",
    result: {
      tools: [{
        name: "send_email",
        description: "Send an email message.",
        inputSchema: {},
        annotations: { destructiveHint: true }
      }]
    }
  });
}

function makeConfig(dir) {
  return {
    stateDir: dir,
    policy: "unused",
    lockfile: join(dir, "palizade.lock"),
    audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false, errorVerbosity: true },
    approvals: { mode: "static-deny", timeoutMs: 10, default: "deny" },
    detectors: {
      heuristic: false,
      promptGuard2: { enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" },
      secrets: { enabled: false, aws: true, generic: true, jwt: true, privateKey: true, googleApiKey: true, stripe: true, slack: true, github: true, openai: true },
      pii: { enabled: true, email: true, ssn: true, creditCard: true, phone: true }
    },
    egress: { allowlist: { hosts: [], emails: [] } },
    transport: { maxMessageBytes: 67108864, maxBufferedBytes: 67108864, allowBatches: false, allowContentLength: false },
    taint: {
      sqlite: join(dir, "taint.sqlite"),
      keyPath: join(dir, "taint.key"),
      scope: "profile",
      profileId: "pii-redact-demo",
      ttlMs: 86400000,
      suspiciousScore: 0.35,
      fuzzyHammingMax: 7,
      temporal: { enabled: true, turns: 3, ttlMs: 300000, detectorScoreGte: 0.55 }
    },
    servers: {
      mail: {
        command: "mail-sender",
        args: [],
        cwd: process.cwd(),
        env: {},
        trust: "semi",
        toolClasses: { send_email: "sink" },
        toolCapabilities: { send_email: ["sends_message"] },
        sensitive: false,
        sensitiveTools: {},
        sensitivePathPatterns: [],
        shell: false,
        allowShell: false
      }
    }
  };
}
