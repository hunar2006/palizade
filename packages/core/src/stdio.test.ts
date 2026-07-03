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
