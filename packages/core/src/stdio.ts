import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import type { Readable, Writable } from "node:stream";
import type { InterceptionEngine } from "./interceptor.js";
import type { JsonRpcEnvelope, JsonRpcMessage } from "./mcp.js";
import type { ServerConfig } from "./config.js";
import type { PalisadeConfig } from "./config.js";

export class LineJsonRpcPeer extends EventEmitter {
  private buffer = Buffer.alloc(0);
  private readonly maxMessageBytes: number;
  private readonly maxBufferedBytes: number;
  private readonly allowBatches: boolean;
  private readonly allowContentLength: boolean;

  constructor(private readonly input: Readable, private readonly output: Writable, options: { maxMessageBytes?: number; maxBufferedBytes?: number; allowBatches?: boolean; allowContentLength?: boolean } = {}) {
    super();
    this.maxMessageBytes = options.maxMessageBytes ?? 64 * 1024 * 1024;
    this.maxBufferedBytes = options.maxBufferedBytes ?? this.maxMessageBytes;
    this.allowBatches = options.allowBatches ?? false;
    this.allowContentLength = options.allowContentLength ?? false;
    this.input.on("data", (chunk) => this.onData(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8")));
    this.input.on("end", () => this.emit("end"));
    this.input.on("error", (error) => this.emit("error", error));
  }

  send(message: JsonRpcEnvelope): void {
    this.output.write(`${JSON.stringify(message)}\n`);
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > this.maxBufferedBytes) {
      this.emit("error", new Error(`JSON-RPC buffer exceeded ${this.maxBufferedBytes} bytes`));
      this.buffer = Buffer.alloc(0);
      return;
    }

    while (this.buffer.length > 0) {
      const framed = this.allowContentLength ? this.tryReadContentLengthFrame() : undefined;
      if (framed === "need-more") {
        return;
      }
      if (framed) {
        this.emitEnvelope(framed);
        continue;
      }

      const newline = this.buffer.indexOf(0x0a);
      if (newline === -1) {
        return;
      }
      const line = this.buffer.toString("utf8", 0, newline).replace(/\r$/u, "").trim();
      this.buffer = this.buffer.subarray(newline + 1);
      if (Buffer.byteLength(line, "utf8") > this.maxMessageBytes) {
        this.emit("error", new Error(`JSON-RPC message exceeded ${this.maxMessageBytes} bytes`));
        continue;
      }
      if (line.length > 0) {
        this.emitEnvelope(line);
      }
    }
  }

  private tryReadContentLengthFrame(): string | "need-more" | undefined {
    const headerEnd = this.buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      return undefined;
    }

    const header = this.buffer.toString("ascii", 0, headerEnd);
    if (!/^content-length:/imu.test(header)) {
      return undefined;
    }

    const match = /^content-length:\s*(\d+)\s*$/imu.exec(header);
    if (!match) {
      this.emit("error", new Error("Invalid Content-Length JSON-RPC frame"));
      this.buffer = this.buffer.subarray(headerEnd + 4);
      return "";
    }

    const length = Number(match[1]);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (this.buffer.length < bodyEnd) {
      return "need-more";
    }

    const body = this.buffer.toString("utf8", bodyStart, bodyEnd);
    this.buffer = this.buffer.subarray(bodyEnd);
    return body;
  }

  private emitEnvelope(raw: string): void {
    if (!raw) {
      return;
    }
    try {
      const parsed = JSON.parse(raw) as JsonRpcEnvelope;
      if (Array.isArray(parsed) && parsed.length === 0) {
        throw new Error("Empty JSON-RPC batch is invalid");
      }
      if (Array.isArray(parsed) && !this.allowBatches) {
        throw new Error("JSON-RPC batches are disabled by default");
      }
      this.emit("message", parsed);
    } catch (error) {
      this.emit("error", error);
    }
  }
}

export interface StdioProxyOptions {
  serverName: string;
  server: ServerConfig;
  transport?: PalisadeConfig["transport"];
  engine: InterceptionEngine;
}

export class StdioMcpProxy {
  private child: ChildProcessWithoutNullStreams | undefined;

  constructor(private readonly options: StdioProxyOptions) {}

  async run(): Promise<void> {
    assertSafeSpawn(this.options.server);
    const child = spawn(resolveCommandForPlatform(this.options.server.command), this.options.server.args, {
      cwd: this.options.server.cwd,
      env: { ...process.env, ...this.options.server.env },
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true
    });
    this.child = child;

    child.stderr.on("data", (chunk) => {
      process.stderr.write(`[palisade:${this.options.serverName}:stderr] ${String(chunk)}`);
    });
    child.on("exit", (code, signal) => {
      process.stderr.write(`[palisade:${this.options.serverName}] upstream exited code=${code ?? "null"} signal=${signal ?? "null"}\n`);
      process.exitCode = code ?? 1;
    });

    const peerOptions = {
      ...(this.options.transport?.maxMessageBytes !== undefined ? { maxMessageBytes: this.options.transport.maxMessageBytes } : {}),
      ...(this.options.transport?.maxBufferedBytes !== undefined ? { maxBufferedBytes: this.options.transport.maxBufferedBytes } : {}),
      ...(this.options.transport?.allowBatches !== undefined ? { allowBatches: this.options.transport.allowBatches } : {}),
      ...(this.options.transport?.allowContentLength !== undefined ? { allowContentLength: this.options.transport.allowContentLength } : {})
    };
    const client = new LineJsonRpcPeer(process.stdin, process.stdout, peerOptions);
    const server = new LineJsonRpcPeer(child.stdout, child.stdin, peerOptions);
    let clientQueue = Promise.resolve();
    let serverQueue = Promise.resolve();

    client.on("message", (message: JsonRpcEnvelope) => {
      clientQueue = clientQueue.then(async () => {
        const output = await handleEnvelope(message, (item) => this.options.engine.handleClientMessage(item));
        if (output.toClient.length > 0) client.send(envelopeFor(output.toClient, Array.isArray(message)));
        if (output.toServer.length > 0) server.send(envelopeFor(output.toServer, Array.isArray(message)));
      }).catch((error: unknown) => {
        process.stderr.write(`[palisade:${this.options.serverName}] client message error: ${formatError(error)}\n`);
      });
    });
    server.on("message", (message: JsonRpcEnvelope) => {
      serverQueue = serverQueue.then(async () => {
        const output = await handleEnvelope(message, (item) => this.options.engine.handleServerMessage(item));
        if (output.toClient.length > 0) client.send(envelopeFor(output.toClient, Array.isArray(message)));
        if (output.toServer.length > 0) server.send(envelopeFor(output.toServer, Array.isArray(message)));
      }).catch((error: unknown) => {
        process.stderr.write(`[palisade:${this.options.serverName}] server message error: ${formatError(error)}\n`);
      });
    });
    client.on("end", () => {
      clientQueue.finally(() => {
        child.stdin.end();
      }).catch(() => {
        child.stdin.end();
      });
    });
  }
}

export async function collectToolsFromStdioServer(server: ServerConfig, timeoutMs = 5_000): Promise<unknown[]> {
  assertSafeSpawn(server);
  const child = spawn(resolveCommandForPlatform(server.command), server.args, {
    cwd: server.cwd,
    env: { ...process.env, ...server.env },
    stdio: ["pipe", "pipe", "pipe"],
    shell: false,
    windowsHide: true
  });
  const peer = new LineJsonRpcPeer(child.stdout, child.stdin);
  const id = randomUUID();

  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Timed out waiting for tools/list"));
    }, timeoutMs);

    peer.on("message", (message: JsonRpcMessage) => {
      if ("id" in message && message.id === id && "result" in message) {
        clearTimeout(timeout);
        child.kill();
        resolve(((message.result as { tools?: unknown[] }).tools) ?? []);
      }
      if ("id" in message && message.id === id && "error" in message) {
        clearTimeout(timeout);
        child.kill();
        reject(new Error(message.error.message));
      }
    });
    peer.on("error", (error) => {
      clearTimeout(timeout);
      child.kill();
      reject(error);
    });
    peer.send({ jsonrpc: "2.0", id, method: "tools/list", params: {} });
  });
}

async function handleEnvelope(
  envelope: JsonRpcEnvelope,
  handler: (message: JsonRpcMessage) => Promise<{ toClient: JsonRpcMessage[]; toServer: JsonRpcMessage[] }>
): Promise<{ toClient: JsonRpcMessage[]; toServer: JsonRpcMessage[] }> {
  const messages = Array.isArray(envelope) ? envelope : [envelope];
  const toClient: JsonRpcMessage[] = [];
  const toServer: JsonRpcMessage[] = [];
  for (const message of messages) {
    const output = await handler(message);
    toClient.push(...output.toClient);
    toServer.push(...output.toServer);
  }
  return { toClient, toServer };
}

function envelopeFor(messages: JsonRpcMessage[], preferBatch: boolean): JsonRpcEnvelope {
  return preferBatch ? messages : messages[0]!;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function assertSafeSpawn(server: ServerConfig): void {
  if (server.shell && !server.allowShell) {
    throw new Error("Unsafe server config: shell execution requires allowShell: true");
  }
}

export function resolveCommandForPlatform(command: string): string {
  if (process.platform !== "win32" || isAbsolute(command) || /\.[a-z0-9]+$/iu.test(command)) {
    return command;
  }
  const pathEntries = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  const extensions = (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  for (const entry of pathEntries) {
    for (const ext of extensions) {
      const candidate = join(entry, `${command}${ext.toLowerCase()}`);
      if (existsSync(candidate)) {
        return candidate;
      }
      const upper = join(entry, `${command}${ext.toUpperCase()}`);
      if (existsSync(upper)) {
        return upper;
      }
    }
  }
  return command;
}
