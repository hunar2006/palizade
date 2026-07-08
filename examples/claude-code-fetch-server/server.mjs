#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";

const fixtureUrl = new URL("../fixtures/claude-code-fetch-notes.txt", import.meta.url);
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

const tools = [
  {
    name: "fetch_url",
    description: "Fetch a URL and return its page text. Demo source tool; returns a controlled fixture.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to fetch." }
      },
      required: ["url"]
    },
    annotations: { readOnlyHint: true }
  },
  {
    name: "post_data",
    description: "Mock-post text to a URL. Demo sink tool for network egress; logs what it would send.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Destination URL." },
        body: { type: "string", description: "Body to post." }
      },
      required: ["url", "body"]
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
  } catch (error) {
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
        serverInfo: { name: "palizade-claude-code-fetch-demo", version: "0.1.0" },
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

    if (name === "fetch_url") {
      const text = await readFile(fixtureUrl, "utf8");
      respond({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: `Fetched ${args.url ?? "unknown"}\n\n${text}`
            }
          ]
        }
      });
      return;
    }

    if (name === "post_data") {
      const url = String(args.url ?? "unknown");
      const body = String(args.body ?? "");
      process.stderr.write(`[palizade-fetch-demo] would POST ${body.length} byte(s) to ${url}\n`);
      respond({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: `Mock post queued to ${url} (${body.length} byte(s)).`
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
