#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";

const fixtureUrl = new URL("../fixtures/malicious-email-message.txt", import.meta.url);
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

const tools = [
  {
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
  },
  {
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
  }
];

rl.on("line", (line) => {
  if (!line.trim()) {
    return;
  }

  let message;
  try {
    message = JSON.parse(line);
  } catch {
    respond({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" }
    });
    return;
  }

  handle(message).catch((error) => {
    if (message.id === undefined) {
      return;
    }
    respond({
      jsonrpc: "2.0",
      id: message.id,
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : String(error)
      }
    });
  });
});

async function handle(message) {
  if (message.id === undefined) {
    return;
  }

  if (message.method === "initialize") {
    respond({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "palizade-mock-email-demo", version: "0.1.0" },
        capabilities: { tools: {} }
      }
    });
    return;
  }

  if (message.method === "ping") {
    respond({ jsonrpc: "2.0", id: message.id, result: {} });
    return;
  }

  if (message.method === "tools/list") {
    respond({ jsonrpc: "2.0", id: message.id, result: { tools } });
    return;
  }

  if (message.method === "tools/call") {
    const name = message.params?.name;
    const args = message.params?.arguments ?? {};

    if (name === "read_message") {
      const text = await readFile(fixtureUrl, "utf8");
      respond({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: `Message ${args.id ?? "unknown"}\n\n${text}`
            }
          ]
        }
      });
      return;
    }

    if (name === "send_email") {
      const to = String(args.to ?? "unknown");
      const subject = String(args.subject ?? "");
      const body = String(args.body ?? "");
      process.stderr.write(`[palizade-email-demo] would send email to ${to} subject="${subject}" body_bytes=${body.length}\n`);
      respond({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: `Mock email queued to ${to} (${body.length} byte(s)).`
            }
          ]
        }
      });
      return;
    }

    respond({
      jsonrpc: "2.0",
      id: message.id,
      error: { code: -32602, message: `Unknown tool '${String(name)}'.` }
    });
    return;
  }

  respond({
    jsonrpc: "2.0",
    id: message.id,
    error: { code: -32601, message: `Unknown method '${String(message.method)}'.` }
  });
}

function respond(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
