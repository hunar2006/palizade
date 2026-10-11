import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticApprovalProvider } from "@palizade/approvals";
import { AuditLogger, type AuditEvent } from "@palizade/audit";
import { HeuristicDetector } from "@palizade/detectors";
import { parsePolicy } from "@palizade/policy";
import { InMemoryTaintStore } from "@palizade/taint";
import { describe, expect, it } from "vitest";
import { HttpMcpTransport, SseParser, decodeHeaderValue, encodeHeaderValue, isLocalhostOrigin, type TransportSecurityEvent } from "./http.js";
import { HttpServeListener } from "./http-listener.js";
import { InterceptionEngine } from "./interceptor.js";
import { LockfileStore } from "./lockfile.js";
import type { PalizadeConfig, ServerConfig } from "./config.js";
import type { JsonRpcMessage } from "./mcp.js";

const policy = parsePolicy(`version: 1
defaults: { action: allow, on_error: block }
rules:
  - id: block-tainted-sink
    when: { direction: request, method: tools/call, tool_class: sink, taint: true }
    action: block
    reason: tainted content flowing into sink tool
`);

function urlServer(url: string): ServerConfig {
  return {
    url,
    args: [],
    env: {},
    headers: {},
    protocolVersion: "auto",
    trust: "untrusted",
    toolClasses: {},
    toolCapabilities: {},
    argumentRoles: {},
    sensitive: false,
    sensitiveTools: {},
    sensitivePathPatterns: [],
    shell: false,
    allowShell: false
  };
}

const httpLimits = {
  requestTimeoutMs: 5_000,
  maxBodyBytes: 1024 * 1024,
  maxSseLineBytes: 1024 * 1024,
  maxSseEventBytes: 1024 * 1024,
  maxConcurrentStreams: 8,
  maxRedirects: 5
};

async function listen(server: HttpServer): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

describe("HTTP transport header codec", () => {
  it("round trips plain and encoded header values", () => {
    expect(encodeHeaderValue("us-west1")).toBe("us-west1");
    expect(encodeHeaderValue("Hello, 世界")).toBe("=?base64?SGVsbG8sIOS4lueVjA==?=");
    expect(decodeHeaderValue("=?base64?SGVsbG8sIOS4lueVjA==?=")).toBe("Hello, 世界");
    expect(encodeHeaderValue("=?base64?literal?=")).toBe("=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=");
    expect(encodeHeaderValue(" padded ")).toBe("=?base64?IHBhZGRlZCA=?=");
  });

  it("classifies localhost origins only", () => {
    expect(isLocalhostOrigin("http://127.0.0.1:32146")).toBe(true);
    expect(isLocalhostOrigin("http://localhost:3000")).toBe(true);
    expect(isLocalhostOrigin("http://evil.example")).toBe(false);
  });
});

describe("SseParser", () => {
  it("parses data, event and id fields and skips comments", () => {
    const events: Array<{ event?: string; data: string; id?: string }> = [];
    const parser = new SseParser({ maxLineBytes: 4096, maxEventBytes: 65536 });
    parser.feed(": keepalive\n\nevent: progress\ndata: {\"a\":1}\n\nid: 7\ndata: {\"b\":2}\n\n", (event) => events.push(event));
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({ event: "progress", data: "{\"a\":1}" });
    expect(events[1]).toEqual({ event: undefined, data: "{\"b\":2}", id: "7" });
  });
});

describe("HttpMcpTransport (2026-07-28)", () => {
  it("sends modern POSTs with metadata headers and receives a JSON response", async () => {
    const upstream = createHttpServer((request, response) => {
      expect(request.headers["mcp-protocol-version"]).toBe("2026-07-28");
      expect(request.headers["mcp-method"]).toBe("tools/list");
      expect(request.headers.accept).toContain("text/event-stream");
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { tools: [{ name: "tool-a" }], _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
      }));
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      const messages: JsonRpcMessage[] = [];
      transport.on("message", (message: JsonRpcMessage) => messages.push(message));
      await transport.send({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
      });
      expect(messages).toHaveLength(1);
      expect(messages[0]).toMatchObject({ id: 1, result: { tools: [{ name: "tool-a" }] } });
    } finally {
      upstream.close();
    }
  });

  it("reads request scoped SSE responses (notifications then the final response)", async () => {
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "text/event-stream" });
      response.write("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n");
      response.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } })}\n\n`);
      response.end();
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      const messages: JsonRpcMessage[] = [];
      transport.on("message", (message: JsonRpcMessage) => messages.push(message));
      await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tool-a", arguments: {}, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } });
      expect(messages).toHaveLength(2);
      expect(messages[0]).toMatchObject({ method: "notifications/progress" });
      expect(messages[1]).toMatchObject({ id: 1, result: { ok: true } });
    } finally {
      upstream.close();
    }
  });

  it("flags a server that pushes a JSON-RPC request on SSE in the new era", async () => {
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "text/event-stream" });
      response.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 9, method: "sampling/createMessage", params: {} })}\n\n`);
      response.end();
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      const violations: TransportSecurityEvent[] = [];
      const messages: JsonRpcMessage[] = [];
      transport.on("securityEvent", (event: TransportSecurityEvent) => violations.push(event));
      transport.on("message", (message: JsonRpcMessage) => messages.push(message));
      await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } });
      expect(violations.some((event) => event.kind === "protocol_violation")).toBe(true);
      expect(messages).toHaveLength(0);
    } finally {
      upstream.close();
    }
  });

  it("rejects header/body disagreement from the upstream", async () => {
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25"
      });
      response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { ok: true, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
      }));
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      const violations: TransportSecurityEvent[] = [];
      transport.on("securityEvent", (event: TransportSecurityEvent) => violations.push(event));
      await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } });
      expect(violations.some((event) => event.kind === "header_mismatch")).toBe(true);
    } finally {
      upstream.close();
    }
  });

  it("mirrors x-mcp-header parameters into Mcp-Param headers with sentinel encoding", async () => {
    let seenHeader: string | undefined;
    const upstream = createHttpServer((request, response) => {
      seenHeader = request.headers["mcp-param-region"] as string | undefined;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      transport.updateToolSchemas([{
        name: "execute_sql",
        inputSchema: {
          type: "object",
          properties: {
            region: { type: "string", "x-mcp-header": "Region" },
            query: { type: "string" }
          }
        }
      }]);
      await transport.send({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "execute_sql", arguments: { region: "Hello, 世界" }, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
      });
      expect(seenHeader).toBe("=?base64?SGVsbG8sIOS4lueVjA==?=");
    } finally {
      upstream.close();
    }
  });
});

describe("HttpMcpTransport (legacy 2025-11-25)", () => {
  it("runs the session round trip: initialize, session id, GET SSE stream, DELETE", async () => {
    let deleted = false;
    const upstream = createHttpServer((request, response) => {
      if (request.method === "DELETE") {
        deleted = true;
        response.writeHead(200);
        response.end();
        return;
      }
      if (request.method === "GET") {
        response.writeHead(200, { "Content-Type": "text/event-stream" });
        response.write(`data: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: {} })}\n\n`);
        return;
      }
      let body = "";
      request.on("data", (chunk) => { body += chunk; });
      request.on("end", () => {
        const message = JSON.parse(body) as JsonRpcMessage;
        if ("method" in message && message.method === "initialize") {
          response.writeHead(200, { "Content-Type": "application/json", "Mcp-Session-Id": "session-123" });
          response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "legacy", version: "1" } } }));
          return;
        }
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { ok: true } }));
      });
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits, protocolVersion: "2025-11-25" });
      const messages: JsonRpcMessage[] = [];
      transport.on("message", (message: JsonRpcMessage) => messages.push(message));
      await transport.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "client", version: "1" } } });
      expect(transport.legacySession).toBe("session-123");
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(messages.some((message) => "method" in message && message.method === "notifications/message")).toBe(true);
      await transport.close();
      expect(deleted).toBe(true);
    } finally {
      upstream.close();
    }
  });

  it("auto-detects a modern server from a 404 with a modern JSON-RPC error and synthesizes initialize", async () => {
    const upstream = createHttpServer((request, response) => {
      if (request.headers["mcp-protocol-version"]) {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }));
        return;
      }
      response.writeHead(404, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "Method not found: initialize" } }));
    });
    const url = await listen(upstream);
    try {
      const transport = new HttpMcpTransport({ serverName: "test", server: urlServer(url), http: httpLimits });
      const messages: JsonRpcMessage[] = [];
      transport.on("message", (message: JsonRpcMessage) => messages.push(message));
      await transport.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
      expect(transport.currentEra).toBe("2026-07-28");
      expect(messages[0]).toMatchObject({ id: 1, result: { protocolVersion: "2026-07-28" } });
    } finally {
      upstream.close();
    }
  });

  it("refuses redirects while Authorization is set (never forwards the token)", async () => {
    const target = createHttpServer((request, response) => {
      expect(request.headers.authorization).toBeUndefined();
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    const targetUrl = await listen(target);
    const redirector = createHttpServer((request, response) => {
      response.writeHead(302, { Location: targetUrl });
      response.end();
    });
    const url = await listen(redirector);
    try {
      const server = urlServer(url);
      server.headers = { Authorization: "Bearer secret-token-xyz" };
      const transport = new HttpMcpTransport({ serverName: "test", server, http: httpLimits, protocolVersion: "2026-07-28" });
      const events: TransportSecurityEvent[] = [];
      transport.on("securityEvent", (event: TransportSecurityEvent) => events.push(event));
      await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } }))
        .rejects.toThrow(/redirect/i);
      expect(events.some((event) => event.kind === "token_never_forwarded")).toBe(true);
    } finally {
      redirector.close();
      target.close();
    }
  });
});

async function makeEngineWithAudit(dir: string): Promise<{ engine: InterceptionEngine; events: AuditEvent[] }> {
  const events: AuditEvent[] = [];
  const config: PalizadeConfig = {
    stateDir: dir, protectedTargets: { criticalPaths: [], maxDiffBytes: 65536 }, limits: { sinkCallsPerMinute: 60, distinctDestinations: 20, repeatThreshold: 5, historyEntries: 1000 },
    policy: join(dir, "policy.yaml"),
    lockfile: join(dir, "palizade.lock"),
    audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false, errorVerbosity: true },
    approvals: { mode: "static-deny", timeoutMs: 10, default: "deny", host: "127.0.0.1", port: 32_145, openBrowser: true },
    detectors: {
      heuristic: true,
      promptGuard2: { enabled: false, model: "x", device: "cpu" },
      secrets: { enabled: false, aws: true, generic: true, jwt: true, privateKey: true, googleApiKey: true, stripe: true, slack: true, github: true, openai: true },
      pii: { enabled: false, email: true, ssn: true, creditCard: true, phone: true }
    },
    egress: {
      mode: "open",
      learnedFile: join(dir, "palizade.allow.yaml"),
      allowlist: { hosts: [], emails: [], destinations: [] }
    },
    transport: { maxMessageBytes: 67108864, maxBufferedBytes: 67108864, allowBatches: false, allowContentLength: false },
    http: httpLimits,
    listener: { host: "127.0.0.1", port: 0, tokenPath: join(dir, "listener.token"), allowRemote: false },
    hooks: { failMode: "closed", timeoutMs: 30_000, maxInputBytes: 1048576 },
    taint: { exposure: { ttlMs: 7_200_000 }, quarantine: { scoreGte: 0.85, turns: 20, ttlMs: 1800000 },
      window: { calls: 12, ttlMs: 900_000, maxBytes: 262144, maxDestinations: 256 },
      decode: { maxDepth: 2, maxBytes: 262144 },
      sqlite: join(dir, "taint.sqlite"),
      keyPath: join(dir, "taint.key"),
      scope: "profile",
      profileId: "test",
      ttlMs: 86_400_000,
      suspiciousScore: 0.35,
      fuzzyHammingMax: 7,
      temporal: { enabled: true, turns: 3, ttlMs: 300_000, detectorScoreGte: 0.55 }
    },
    servers: { toy: urlServer("http://127.0.0.1:1") }
  };
  const engine = new InterceptionEngine({
    config,
    serverName: "toy",
    server: config.servers.toy!,
    sessionId: "test-session",
    policy,
    detector: new HeuristicDetector(),
    taintStore: new InMemoryTaintStore(),
    audit: new AuditLogger([{ write: async (event) => { events.push(event); } }], { captureRawPayloads: false }),
    approvals: new StaticApprovalProvider(false, "test denies approval"),
    lockfile: new LockfileStore(config.lockfile)
  });
  return { engine, events };
}

describe("taint enforcement over HTTP", () => {
  it("blocks a tainted sink over HTTP exactly as over stdio", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-http-"));
    const upstream = createHttpServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => { body += chunk; });
      request.on("end", () => {
        const message = JSON.parse(body) as JsonRpcMessage;
        if ("method" in message && message.method === "tools/list") {
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              tools: [
                { name: "read_web", description: "Read page", inputSchema: {}, annotations: { readOnlyHint: true } },
                { name: "send_email", description: "Send email", inputSchema: {}, annotations: { destructiveHint: true } }
              ]
            }
          }));
          return;
        }
        if ("method" in message && message.method === "tools/call") {
          const params = message.params as { name: string };
          const text = params.name === "read_web"
            ? "Quarterly report data from untrusted source"
            : "sent";
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text }] } }));
          return;
        }
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {} }));
      });
    });
    const url = await listen(upstream);
    try {
      const { engine, events } = await makeEngineWithAudit(dir);
      const transport = new HttpMcpTransport({ serverName: "toy", server: urlServer(url), http: httpLimits, protocolVersion: "2026-07-28" });
      const route = async (message: JsonRpcMessage): Promise<JsonRpcMessage[]> => {
        const output = await engine.handleClientMessage(message);
        const toClient: JsonRpcMessage[] = [...output.toClient];
        for (const item of output.toServer) {
          await transport.send(item);
        }
        return toClient;
      };
      transport.on("message", (message: JsonRpcMessage) => {
        void (async () => {
          const output = await engine.handleServerMessage(message);
          for (const item of output.toClient) {
            void item;
          }
        })();
      });

      await route({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
      await new Promise((resolve) => setTimeout(resolve, 50));
      await route({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_web", arguments: { url: "https://example.test/report" } } });
      await new Promise((resolve) => setTimeout(resolve, 50));
      const sinkOutput = await route({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "send_email", arguments: { to: "ops@example.test", body: "Quarterly report data from untrusted source" } }
      });
      expect(sinkOutput).toHaveLength(1);
      expect(sinkOutput[0]).toMatchObject({ result: { isError: true } });
      expect(JSON.stringify(sinkOutput[0])).toContain("tainted content flowing into sink tool");
      const blockEvent = events.find((event) => event.action === "block" && event.matched_rule?.id === "block-tainted-sink");
      expect(blockEvent).toBeDefined();
      await transport.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("HttpServeListener", () => {
  async function makeListener(dir: string, upstreamUrl: string, extra: { token?: string } = {}) {
    const { engine } = await makeEngineWithAudit(dir);
    const listener = new HttpServeListener({
      config: {
        stateDir: dir, protectedTargets: { criticalPaths: [], maxDiffBytes: 65536 }, limits: { sinkCallsPerMinute: 60, distinctDestinations: 20, repeatThreshold: 5, historyEntries: 1000 },
        policy: join(dir, "policy.yaml"),
        lockfile: join(dir, "palizade.lock"),
        audit: { jsonl: join(dir, "audit.jsonl"), sqlite: join(dir, "audit.sqlite"), captureRawPayloads: false, errorVerbosity: true },
        approvals: { mode: "static-deny", timeoutMs: 10, default: "deny", host: "127.0.0.1", port: 32_145, openBrowser: true },
        detectors: {
          heuristic: true,
          promptGuard2: { enabled: false, model: "x", device: "cpu" },
          secrets: { enabled: false, aws: true, generic: true, jwt: true, privateKey: true, googleApiKey: true, stripe: true, slack: true, github: true, openai: true },
          pii: { enabled: false, email: true, ssn: true, creditCard: true, phone: true }
        },
        egress: {
          mode: "open",
          learnedFile: join(dir, "palizade.allow.yaml"),
          allowlist: { hosts: [], emails: [], destinations: [] }
        },
        transport: { maxMessageBytes: 67108864, maxBufferedBytes: 67108864, allowBatches: false, allowContentLength: false },
        http: httpLimits,
        listener: { host: "127.0.0.1", port: 0, tokenPath: join(dir, "listener.token"), allowRemote: false },
        hooks: { failMode: "closed", timeoutMs: 30_000, maxInputBytes: 1048576 },
        taint: { exposure: { ttlMs: 7_200_000 }, quarantine: { scoreGte: 0.85, turns: 20, ttlMs: 1800000 },
          window: { calls: 12, ttlMs: 900_000, maxBytes: 262144, maxDestinations: 256 },
          decode: { maxDepth: 2, maxBytes: 262144 },
          sqlite: join(dir, "taint.sqlite"),
          keyPath: join(dir, "taint.key"),
          scope: "profile",
          profileId: "test",
          ttlMs: 86_400_000,
          suspiciousScore: 0.35,
          fuzzyHammingMax: 7,
          temporal: { enabled: true, turns: 3, ttlMs: 300_000, detectorScoreGte: 0.55 }
        },
        servers: { toy: urlServer(upstreamUrl) }
      },
      token: extra.token ?? "test-token-abcdef",
      createRuntime: async () => ({ engine })
    });
    const bound = await listener.start();
    return { listener, url: `http://127.0.0.1:${bound.port}` };
  }

  it("rejects requests without the listener bearer token", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const response = await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      expect(response.status).toBe(401);
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects non localhost Origin headers", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const response = await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Palizade-Token": "test-token-abcdef",
          Origin: "http://evil.example"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      expect(response.status).toBe(403);
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects header/body disagreement with 400 and -32020", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const response = await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Palizade-Token": "test-token-abcdef",
          "MCP-Protocol-Version": "2025-11-25",
          "Mcp-Method": "tools/list"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
        })
      });
      expect(response.status).toBe(400);
      const body = await response.json() as { error: { code: number } };
      expect(body.error.code).toBe(-32020);
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("forwards the client Authorization header only to the configured upstream", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    let seenAuthorization: string | undefined;
    const upstream = createHttpServer((request, response) => {
      seenAuthorization = request.headers.authorization as string | undefined;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const response = await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Palizade-Token": "test-token-abcdef",
          Authorization: "Bearer client-oauth-token"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      expect(response.status).toBe(200);
      expect(seenAuthorization).toBe("Bearer client-oauth-token");
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("passes upstream 401 and WWW-Authenticate through untouched", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    const upstream = createHttpServer((request, response) => {
      response.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": "Bearer resource_metadata=\"https://example.test/metadata\", scope=\"read\""
      });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32030, message: "Unauthorized" } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const response = await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Palizade-Token": "test-token-abcdef"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toContain("resource_metadata");
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("never logs the Authorization token", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-listener-"));
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }));
    });
    const upstreamUrl = await listen(upstream);
    try {
      const { listener, url } = await makeListener(dir, upstreamUrl);
      const secret = "super-secret-client-token-value";
      await fetch(`${url}/mcp/toy`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Palizade-Token": "test-token-abcdef",
          Authorization: `Bearer ${secret}`
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      const auditRaw = await readFile(join(dir, "audit.jsonl"), "utf8").catch(() => "");
      expect(auditRaw).not.toContain(secret);
      await listener.close();
    } finally {
      upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
