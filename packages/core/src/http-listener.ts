import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { HttpMcpTransport, SseParser, decodeHeaderValue, encodeSseEvent, isLocalhostOrigin, protocolVersionOf, resolveHeaderTemplates, type TransportSecurityEvent } from "./http.js";
import { isRequest, makeErrorResponse, type JsonRpcMessage } from "./mcp.js";
import type { PalizadeConfig } from "./config.js";
import type { InterceptionEngine } from "./interceptor.js";
import type { McpTool } from "./mcp.js";

export interface HttpListenerRuntime {
  engine: InterceptionEngine;
}

export interface HttpListenerOptions {
  config: PalizadeConfig;
  host?: string;
  port?: number;
  allowRemote?: boolean;
  token?: string;
  onSecurityEvent?: (event: TransportSecurityEvent) => void;
  createRuntime: (serverName: string) => Promise<HttpListenerRuntime>;
}

interface UpstreamSession {
  engine: InterceptionEngine;
  transport: HttpMcpTransport;
  lastUpstreamAuthChallenge?: { status: number; wwwAuthenticate?: string };
}

export class HttpServeListener {
  private server: Server | undefined;
  private readonly sessions = new Map<string, UpstreamSession>();
  private token: string;

  constructor(private readonly options: HttpListenerOptions) {
    this.token = options.token ?? process.env.PALIZADE_LISTENER_TOKEN ?? "";
  }

  async start(): Promise<{ host: string; port: number }> {
    const host = this.options.host ?? this.options.config.listener.host;
    const port = this.options.port ?? this.options.config.listener.port;
    const allowRemote = this.options.allowRemote ?? this.options.config.listener.allowRemote;
    if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1" && !allowRemote) {
      throw new Error(`Refusing to bind listener to '${host}'; pass --allow-remote to serve non-localhost addresses.`);
    }
    if (this.token.length === 0) {
      this.token = await ensureListenerToken(this.options.config.listener.tokenPath);
    }

    this.server = createServer((request, response) => {
      void this.handle(request, response).catch((error: unknown) => {
        if (!response.headersSent) {
          respondJson(response, 500, makeErrorResponse(null, -32603, error instanceof Error ? error.message : String(error)));
        } else {
          response.end();
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => resolve());
    });
    const address = this.server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    return { host, port: boundPort };
  }

  async close(): Promise<void> {
    if (!this.server) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      this.server!.close((error) => error ? reject(error) : resolve());
    });
    await Promise.all([...this.sessions.values()].map((session) => session.transport.close()));
    this.sessions.clear();
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = (request.url ?? "").split("?")[0] ?? "";
    const match = /^\/mcp\/([^/]+)$/u.exec(path);
    if (!match) {
      respondJson(response, 404, makeErrorResponse(null, -32030, `No MCP endpoint at '${path}'. Use /mcp/<serverName>.`));
      return;
    }
    const serverName = decodeURIComponent(match[1]!);
    const authorization = typeof request.headers.authorization === "string" ? request.headers.authorization : undefined;
    const xToken = typeof request.headers["x-palizade-token"] === "string" ? request.headers["x-palizade-token"] : undefined;
    const authorized = this.token.length > 0 && (
      (xToken !== undefined && safeEqual(xToken, this.token)) ||
      (authorization?.startsWith("Bearer ") && safeEqual(authorization.slice("Bearer ".length), this.token))
    );
    if (!authorized) {
      respondJson(response, 401, makeErrorResponse(null, -32001, "Palizade listener requires its own bearer token (X-Palizade-Token header)."));
      return;
    }
    const origin = request.headers.origin;
    if (typeof origin === "string" && !isLocalhostOrigin(origin)) {
      respondJson(response, 403, makeErrorResponse(null, -32002, `Origin '${origin}' is not a localhost origin.`));
      return;
    }
    const server = this.options.config.servers[serverName];
    if (!server?.url) {
      respondJson(response, 404, makeErrorResponse(null, -32030, `No url server named '${serverName}' in config.`));
      return;
    }
    const session = await this.sessionFor(serverName);
    const clientAuthorization = authorization
      && this.token.length > 0
      && !safeEqual(authorization, `Bearer ${this.token}`)
      ? authorization
      : undefined;

    if (request.method === "POST") {
      await this.handlePost(request, response, serverName, session, clientAuthorization);
      return;
    }
    if (request.method === "GET") {
      await this.handleGetStream(request, response, serverName, session, clientAuthorization);
      return;
    }
    if (request.method === "DELETE") {
      await this.handleDelete(response, serverName, session, clientAuthorization);
      return;
    }
    respondJson(response, 405, makeErrorResponse(null, -32030, `Method ${request.method} not allowed on /mcp/<serverName>.`));
  }

  private async handlePost(
    request: IncomingMessage,
    response: ServerResponse,
    serverName: string,
    session: UpstreamSession,
    clientAuthorization: string | undefined
  ): Promise<void> {
    let raw: string;
    try {
      raw = await readRequestBounded(request, this.options.config.http.maxBodyBytes);
    } catch (error) {
      respondJson(response, 413, makeErrorResponse(null, -32030, error instanceof Error ? error.message : String(error)));
      return;
    }
    let message: JsonRpcMessage;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        respondJson(response, 400, makeErrorResponse(null, -32600, "JSON-RPC batches are disabled on the listener."));
        return;
      }
      message = parsed as JsonRpcMessage;
      if (!isRequest(message) && !("result" in message)) {
        respondJson(response, 400, makeErrorResponse(null, -32600, "Invalid JSON-RPC message."));
        return;
      }
    } catch {
      respondJson(response, 400, makeErrorResponse(null, -32700, "Request body is not valid JSON."));
      return;
    }

    const headerValidation = validateInboundRequestHeaders(request, message);
    if (headerValidation) {
      respondJson(response, 400, headerValidation);
      return;
    }

    const forwardHeaders: Record<string, string> = {};
    if (clientAuthorization) {
      forwardHeaders.Authorization = clientAuthorization;
    }

    const output = await session.engine.handleClientMessage(message);
    const toClient: JsonRpcMessage[] = [...output.toClient];
    const responseWaiters: Array<Promise<JsonRpcMessage> | undefined> = output.toServer.map((outgoing) => {
      if (isRequest(outgoing) && outgoing.id !== undefined) {
        return session.transport.waitForResponse(outgoing.id, this.options.config.http.requestTimeoutMs);
      }
      return undefined;
    });
    for (const outgoing of output.toServer) {
      await session.transport.send(outgoing, forwardHeaders);
    }
    const settled = await Promise.allSettled(responseWaiters.filter((waiter): waiter is Promise<JsonRpcMessage> => waiter !== undefined));
    const upstreamResponses = settled
      .filter((result): result is PromiseFulfilledResult<JsonRpcMessage> => result.status === "fulfilled")
      .map((result) => result.value);
    for (const upstreamResponse of upstreamResponses) {
      const routed = await session.engine.handleServerMessage(upstreamResponse);
      toClient.push(...routed.toClient);
      for (const item of routed.toServer) {
        await session.transport.send(item, forwardHeaders);
      }
      const tools = extractToolsList(upstreamResponse);
      if (tools) {
        session.transport.updateToolSchemas(tools);
      }
    }

    if (message.id === undefined) {
      response.statusCode = 202;
      response.end();
      return;
    }

    let finalResponse = toClient.find((item) => !isRequest(item) && String((item as { id: unknown }).id) === String(message.id))
      ?? toClient.find((item) => !isRequest(item))
      ?? upstreamResponses.find((item) => !isRequest(item));
    const isUpstreamError = finalResponse !== undefined && "error" in finalResponse && (finalResponse as { error: { code: number } }).error.code === -32030;
    if ((finalResponse === undefined || isUpstreamError) && session.lastUpstreamAuthChallenge) {
      const challenge = session.lastUpstreamAuthChallenge;
      response.writeHead(challenge.status, {
        "Content-Type": "application/json",
        ...(challenge.wwwAuthenticate ? { "WWW-Authenticate": challenge.wwwAuthenticate } : {})
      });
      response.end(finalResponse ? JSON.stringify(finalResponse) : "");
      return;
    }
    if (finalResponse === undefined) {
      finalResponse = makeErrorResponse(message.id, -32603, "No response from upstream MCP server.");
    }

    const accept = request.headers.accept ?? "";
    if (accept.includes("text/event-stream")) {
      respondSse(response, toClient.filter((item) => !isRequest(item)));
      return;
    }
    respondJson(response, 200, finalResponse);
  }

  private async handleGetStream(
    request: IncomingMessage,
    response: ServerResponse,
    serverName: string,
    session: UpstreamSession,
    clientAuthorization: string | undefined
  ): Promise<void> {
    const server = this.options.config.servers[serverName]!;
    const sessionId = request.headers["mcp-session-id"];
    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      ...(typeof sessionId === "string" ? { "Mcp-Session-Id": sessionId } : {}),
      ...(typeof request.headers["last-event-id"] === "string" ? { "Last-Event-ID": request.headers["last-event-id"] } : {})
    };
    if (clientAuthorization) {
      headers.Authorization = clientAuthorization;
    }
    const upstreamHeaders = {
      ...resolveHeaderTemplates(server.headers ?? {}),
      ...headers
    };
    const abort = new AbortController();
    request.on("close", () => abort.abort());
    let upstream: Response;
    try {
      upstream = await fetch(server.url!, { method: "GET", headers: upstreamHeaders, redirect: "manual", signal: abort.signal });
    } catch (error) {
      if (!abort.signal.aborted) {
        this.securityEvent(serverName, {
          kind: "upstream_http_error",
          message: `Upstream GET stream failed for '${serverName}': ${error instanceof Error ? error.message : String(error)}`
        });
      }
      if (!response.headersSent) {
        respondJson(response, 502, makeErrorResponse(null, -32030, "Upstream GET stream failed."));
      }
      return;
    }
    if (!upstream.ok || !upstream.body) {
      respondJson(response, upstream.status, makeErrorResponse(null, -32030, `Upstream GET stream returned HTTP ${upstream.status}.`));
      return;
    }
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive"
    });
    const parser = new SseParser({
      maxLineBytes: this.options.config.http.maxSseLineBytes,
      maxEventBytes: this.options.config.http.maxSseEventBytes
    });
    const reader = upstream.body.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        try {
          parser.feed(decoder.decode(value, { stream: true }), (event) => {
            void this.routeUpstreamEvent(event.data, session, serverName, clientAuthorization, response);
          });
        } catch (error) {
          this.securityEvent(serverName, {
            kind: "sse_limit_exceeded",
            message: error instanceof Error ? error.message : String(error)
          });
          break;
        }
      }
    } catch (error) {
      if (!abort.signal.aborted) {
        this.securityEvent(serverName, {
          kind: "upstream_http_error",
          message: `Upstream GET stream interrupted for '${serverName}': ${error instanceof Error ? error.message : String(error)}`
        });
      }
    } finally {
      reader.releaseLock();
      response.end();
    }
  }

  private async routeUpstreamEvent(
    data: string,
    session: UpstreamSession,
    serverName: string,
    clientAuthorization: string | undefined,
    response: ServerResponse
  ): Promise<void> {
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(data) as JsonRpcMessage;
    } catch {
      this.securityEvent(serverName, {
        kind: "upstream_http_error",
        message: `Upstream SSE event carried invalid JSON for '${serverName}'.`
      });
      return;
    }
    const routed = await session.engine.handleServerMessage(message);
    for (const item of routed.toClient) {
      response.write(encodeSseEvent({ data: JSON.stringify(item) }));
    }
    for (const item of routed.toServer) {
      await session.transport.send(item, clientAuthorization ? { Authorization: clientAuthorization } : {});
    }
    const tools = extractToolsList(message);
    if (tools) {
      session.transport.updateToolSchemas(tools);
    }
  }

  private async handleDelete(
    response: ServerResponse,
    serverName: string,
    session: UpstreamSession,
    clientAuthorization: string | undefined
  ): Promise<void> {
    const server = this.options.config.servers[serverName]!;
    const headers = {
      ...resolveHeaderTemplates(server.headers ?? {}),
      ...(session.transport.legacySession ? { "Mcp-Session-Id": session.transport.legacySession } : {}),
      ...(clientAuthorization ? { Authorization: clientAuthorization } : {})
    };
    let upstream: Response;
    try {
      upstream = await fetch(server.url!, { method: "DELETE", headers, redirect: "manual" });
    } catch (error) {
      this.securityEvent(serverName, {
        kind: "upstream_http_error",
        message: `Upstream DELETE failed for '${serverName}': ${error instanceof Error ? error.message : String(error)}`
      });
      respondJson(response, 502, makeErrorResponse(null, -32030, "Upstream DELETE failed."));
      return;
    }
    if (!upstream.ok) {
      respondJson(response, upstream.status, makeErrorResponse(null, -32030, `Upstream DELETE returned HTTP ${upstream.status}.`));
      return;
    }
    response.statusCode = upstream.status === 204 ? 204 : 200;
    response.end();
  }

  private async sessionFor(serverName: string): Promise<UpstreamSession> {
    const existing = this.sessions.get(serverName);
    if (existing) {
      return existing;
    }
    const runtime = await this.options.createRuntime(serverName);
    const server = this.options.config.servers[serverName]!;
    const transport = new HttpMcpTransport({
      serverName,
      server,
      http: this.options.config.http,
      protocolVersion: server.protocolVersion ?? "auto",
      onSecurityEvent: (event) => this.securityEvent(serverName, event)
    });
    const session: UpstreamSession = { engine: runtime.engine, transport };
    transport.on("upstreamStatus", (status: number, headers: Record<string, string | undefined>) => {
      const wwwAuthenticate = headers["www-authenticate"];
      session.lastUpstreamAuthChallenge = {
        status,
        ...(typeof wwwAuthenticate === "string" ? { wwwAuthenticate } : {})
      };
    });
    this.sessions.set(serverName, session);
    return session;
  }

  private securityEvent(serverName: string, event: TransportSecurityEvent): void {
    this.options.onSecurityEvent?.({ ...event, message: `[${serverName}] ${event.message}` });
  }
}

function validateInboundRequestHeaders(request: IncomingMessage, message: JsonRpcMessage): JsonRpcMessage | undefined {
  const bodyVersion = protocolVersionOf(message);
  if (bodyVersion === undefined) {
    return undefined;
  }
  const headerVersion = request.headers["mcp-protocol-version"];
  if (typeof headerVersion !== "string") {
    return makeErrorResponse(null, -32020, "HeaderMismatch: MCP-Protocol-Version header is missing for a 2026-07-28 request.");
  }
  if (headerVersion !== bodyVersion) {
    return makeErrorResponse(null, -32020, `HeaderMismatch: MCP-Protocol-Version header '${headerVersion}' does not match body '${bodyVersion}'.`);
  }
  if (isRequest(message)) {
    const headerMethod = request.headers["mcp-method"];
    if (typeof headerMethod !== "string") {
      return makeErrorResponse(null, -32020, "HeaderMismatch: Mcp-Method header is missing.");
    }
    if (headerMethod !== message.method) {
      return makeErrorResponse(null, -32020, `HeaderMismatch: Mcp-Method header '${headerMethod}' does not match body method '${message.method}'.`);
    }
  }
  const headerName = request.headers["mcp-name"];
  if (typeof headerName === "string" && isRequest(message) && typeof (message.params as Record<string, unknown>)?.name === "string") {
    const bodyName = (message.params as Record<string, unknown>).name as string;
    const decoded = decodeHeaderValue(headerName);
    if (decoded === undefined || decoded !== bodyName) {
      return makeErrorResponse(null, -32020, `HeaderMismatch: Mcp-Name header does not match body params.name.`);
    }
  }
  return undefined;
}

function extractToolsList(message: JsonRpcMessage): McpTool[] | undefined {
  if (isRequest(message) || !("result" in message)) {
    return undefined;
  }
  const result = (message as { result: unknown }).result;
  if (result && typeof result === "object" && Array.isArray((result as { tools?: unknown }).tools)) {
    return (result as { tools: McpTool[] }).tools;
  }
  return undefined;
}

function respondJson(response: ServerResponse, status: number, body: JsonRpcMessage): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

function respondSse(response: ServerResponse, messages: JsonRpcMessage[]): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache"
  });
  for (const message of messages) {
    response.write(encodeSseEvent({ data: JSON.stringify(message) }));
  }
  response.end();
}

function safeEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, "utf8");
  const bBuffer = Buffer.from(b, "utf8");
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return aBuffer.length === 0 ? true : timingSafeEqual(aBuffer, bBuffer);
}

export async function ensureListenerToken(tokenPath: string): Promise<string> {
  try {
    const existing = await readFile(tokenPath, "utf8");
    const trimmed = existing.trim();
    if (trimmed.length >= 32) {
      return trimmed;
    }
  } catch {
    // token does not exist yet
  }
  const token = randomBytes(32).toString("hex");
  await mkdir(dirname(tokenPath), { recursive: true });
  await writeFile(tokenPath, `${token}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await chmod(tokenPath, 0o600);
  } catch {
    // Windows has no POSIX file modes; the default ACL applies.
  }
  return token;
}

async function readRequestBounded(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) {
      throw new Error(`Request body exceeded ${maxBytes} bytes.`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
