import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { LineJsonRpcPeer } from "./stdio.js";
import type { JsonRpcEnvelope } from "./mcp.js";

describe("LineJsonRpcPeer", () => {
  it("parses chunked newline-delimited JSON-RPC", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const peer = new LineJsonRpcPeer(input, output);
    const received = onceMessage(peer);

    input.write('{"jsonrpc":"2.0","method":"no');
    input.write('tifications/initialized","params":{}}\n');

    await expect(received).resolves.toMatchObject({ method: "notifications/initialized" });
  });

  it("rejects Content-Length framing by default", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const peer = new LineJsonRpcPeer(input, output);
    const body = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
    const error = onceError(peer);

    input.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);

    await expect(error.then((err) => err.message)).resolves.toMatch(/JSON|Unexpected|invalid/iu);
  });

  it("parses Content-Length framed JSON-RPC only in compatibility mode", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const peer = new LineJsonRpcPeer(input, output, { allowContentLength: true });
    const body = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
    const received = onceMessage(peer);

    input.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);

    await expect(received).resolves.toMatchObject({ id: 1, method: "ping" });
  });

  it("rejects JSON-RPC batches by default", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const peer = new LineJsonRpcPeer(input, output);
    const error = onceError(peer);

    input.write('[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]\n');

    await expect(error.then((err) => err.message)).resolves.toMatch(/batches/u);
  });

  it("parses and writes JSON-RPC batches in compatibility mode", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const peer = new LineJsonRpcPeer(input, output, { allowBatches: true });
    const received = onceMessage(peer);

    input.write('[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]\n');
    peer.send([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 2, result: {} }
    ]);

    const written = output.read()?.toString("utf8") ?? "";
    expect(JSON.parse(written)).toHaveLength(2);
    await expect(received).resolves.toHaveLength(2);
  });
});

function onceMessage(peer: LineJsonRpcPeer): Promise<JsonRpcEnvelope> {
  return new Promise((resolve, reject) => {
    peer.once("message", resolve);
    peer.once("error", reject);
  });
}

function onceError(peer: LineJsonRpcPeer): Promise<Error> {
  return new Promise((resolve) => {
    peer.once("error", resolve);
  });
}

describe("collectToolsFromStdioServer", () => {
  // A server that, like the Python SDK, rejects requests before initialize, and pages its tools.
  const strictServer = `
    const rl = require("node:readline").createInterface({ input: process.stdin });
    let initialized = false;
    const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
    rl.on("line", (line) => {
      const m = JSON.parse(line);
      if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "s", version: "1" } } });
      if (m.method === "notifications/initialized") { initialized = true; return; }
      if (m.method === "tools/list") {
        if (!initialized) return send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Invalid request parameters" } });
        if (!m.params.cursor) return send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "a", inputSchema: {} }], nextCursor: "p2" } });
        return send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "b", inputSchema: {} }] } });
      }
    });`;

  it("initializes first and follows pagination", async () => {
    const { collectToolsFromStdioServer } = await import("./stdio.js");
    const server = { command: process.execPath, args: ["-e", strictServer], env: {}, headers: {}, protocolVersion: "auto" as const, trust: "untrusted" as const, toolClasses: {}, toolCapabilities: {}, argumentRoles: {}, sensitive: false, sensitiveTools: {}, sensitivePathPatterns: [], shell: false, allowShell: false };
    const tools = await collectToolsFromStdioServer(server, 10_000, { serverName: "strict" }) as Array<{ name: string }>;
    expect(tools.map((tool) => tool.name)).toEqual(["a", "b"]);
  });

  it("reports a server that exits before answering", async () => {
    const { collectToolsFromStdioServer } = await import("./stdio.js");
    const server = { command: process.execPath, args: ["-e", "process.exit(3)"], env: {}, headers: {}, protocolVersion: "auto" as const, trust: "untrusted" as const, toolClasses: {}, toolCapabilities: {}, argumentRoles: {}, sensitive: false, sensitiveTools: {}, sensitivePathPatterns: [], shell: false, allowShell: false };
    await expect(collectToolsFromStdioServer(server, 10_000, { serverName: "dies" })).rejects.toThrow(/exited/u);
  });
});
