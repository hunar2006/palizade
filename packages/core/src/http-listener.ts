import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  HttpMcpTransport,
  SseParser,
  collectXMcpHeaderAnnotations,
  decodeHeaderValue,
  encodeSseEvent,
  isLocalhostHostHeader,
  isLocalhostOrigin,
  lookupPath,
  protocolVersionOf,
  resolveHeaderTemplates,
  resolveUrlTemplate,
  type TransportSecurityEvent
} from "./http.js";
import { isRequest, makeErrorResponse, type JsonRpcId, type JsonRpcMessage, type JsonRpcResponse } from "./mcp.js";
import type { PalizadeConfig, ServerConfig } from "./config.js";
import type { InterceptionEngine } from "./interceptor.js";
import type { McpTool } from "./mcp.js";

export interface HttpListenerRuntime {
  engine: InterceptionEngine;
  close?: () => void | Promise<void>;
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
  id?: string;
  statelessKey?: string;
  serverName: string;
  authorization: string | undefined;
  runtime: HttpListenerRuntime;
  transport: HttpMcpTransport;
  shutdown: AbortController;
  lastUsed: number;
  activeRequests: number;
  pending: Set<JsonRpcId>;
  terminating?: Promise<void>;
}

const SESSION_IDLE_MS = 30 * 60 * 1_000;
const MAX_SESSIONS = 256;
const MAX_SSE_BUFFER_BYTES = 4 * 1024 * 1024;
const MODERN_PROTOCOL_VERSION = "2026-07-28";
const SUPPORTED_PROTOCOL_VERSIONS = new Set([
  MODERN_PROTOCOL_VERSION,
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
  "2024-10-07"
]);

export class HttpServeListener {
  private server: Server | undefined;
  private reapTimer: ReturnType<typeof setInterval> | undefined;
  private shutdown = new AbortController();
  private readonly sessions = new Map<string, UpstreamSession>();
  private readonly stateless = new Map<string, Promise<UpstreamSession | undefined>>();
  private readonly active = new Set<UpstreamSession>();
  private starting = 0;
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

    this.shutdown = new AbortController();
    this.server = createServer((request, response) => {
      void this.handle(request, response).catch((error: unknown) => {
        this.options.onSecurityEvent?.({
          kind: "upstream_http_error",
          message: `Listener request error: ${error instanceof Error ? error.message : String(error)}`
        });
        if (!response.headersSent) {
          respondJson(response, 500, makeErrorResponse(null, -32603, "Internal MCP listener error."), true);
        } else {
          response.end();
        }
      });
    });
    this.reapTimer = setInterval(() => {
      const cutoff = Date.now() - SESSION_IDLE_MS;
      for (const session of this.active) {
        if (session.activeRequests === 0 && session.lastUsed <= cutoff) {
          void this.endSession(session).catch(() => undefined);
        }
      }
    }, 60_000).unref();
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => resolve());
    });
    const address = this.server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    return { host, port: boundPort };
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) {
      return;
    }
    this.server = undefined;
    clearInterval(this.reapTimer);
    this.shutdown.abort();
    const closed = new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    server.closeAllConnections();
    await Promise.all([closed, ...[...this.active].map((session) => this.endSession(session))]);
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const boundHost = this.options.host ?? this.options.config.listener.host;
    const allowRemote = this.options.allowRemote ?? this.options.config.listener.allowRemote;
    const boundHostAuthority = boundHost.includes(":") && !boundHost.startsWith("[") ? `[${boundHost}]` : boundHost;
    if ((!allowRemote || isLocalhostHostHeader(boundHostAuthority)) && !isLocalhostHostHeader(request.headers.host)) {
      respondJson(response, 403, makeErrorResponse(null, -32002, "Host header is not a localhost host."), true);
      return;
    }
    const origin = request.headers.origin;
    if (origin !== undefined && !isLocalhostOrigin(origin)) {
      respondJson(response, 403, makeErrorResponse(null, -32002, `Origin '${origin}' is not a localhost origin.`), true);
      return;
    }
    const path = (request.url ?? "").split("?")[0] ?? "";
    const match = /^\/mcp\/([^/]+)$/u.exec(path);
    if (!match) {
      respondJson(response, 404, makeErrorResponse(null, -32030, `No MCP endpoint at '${path}'. Use /mcp/<serverName>.`), true);
      return;
    }
    const serverName = decodeURIComponent(match[1]!);
    const authorization = typeof request.headers.authorization === "string" ? request.headers.authorization : undefined;
    const xToken = typeof request.headers["x-palizade-token"] === "string" ? request.headers["x-palizade-token"] : undefined;
    const listenerBearer = this.isListenerBearer(authorization);
    const authorized = this.token.length > 0 && ((xToken !== undefined && safeEqual(xToken, this.token)) || listenerBearer);
    if (!authorized) {
      respondJson(response, 401, makeErrorResponse(null, -32001, "Palizade listener requires its own bearer token (X-Palizade-Token header)."), true);
      return;
    }
    const server = this.options.config.servers[serverName];
    if (!server?.url) {
      respondJson(response, 404, makeErrorResponse(null, -32030, `No url server named '${serverName}' in config.`), true);
      return;
    }
    const clientAuthorization = listenerBearer ? undefined : authorization;
    const sessionId = request.headers["mcp-session-id"];
    const session = typeof sessionId === "string" ? this.sessions.get(sessionId) : undefined;
    if (sessionId !== undefined && (session?.serverName !== serverName || session.authorization !== clientAuthorization)) {
      respondJson(response, 404, makeErrorResponse(null, -32030, "MCP session is unknown or expired."), true);
      return;
    }

    if (request.method === "POST") {
      await this.handlePost(request, response, serverName, server, clientAuthorization, session);
      return;
    }
    if (session && (request.method === "GET" || request.method === "DELETE")) {
      session.activeRequests++;
      try {
        if (request.method === "GET") {
          await this.handleGetStream(request, response, session);
        } else {
          await this.endSession(session);
          response.writeHead(204).end();
        }
      } finally {
        await this.releaseSession(session);
      }
      return;
    }
    respondJson(response, 405, makeErrorResponse(null, -32030, `Method ${request.method} not allowed on /mcp/<serverName>.`), true);
  }

  private async handlePost(
    request: IncomingMessage,
    response: ServerResponse,
    serverName: string,
    server: ServerConfig,
    clientAuthorization: string | undefined,
    existing: UpstreamSession | undefined
  ): Promise<void> {
    let raw: string;
    try {
      raw = await readRequestBounded(request, this.options.config.http.maxBodyBytes);
    } catch (error) {
      if (error instanceof PayloadTooLargeError) {
        respondJson(response, 413, makeErrorResponse(null, -32030, error.message), true);
        return;
      }
      if (!request.aborted && !response.destroyed) {
        respondJson(response, 400, makeErrorResponse(null, -32700, "Failed to read request body."), true);
      }
      return;
    }
    let message: JsonRpcMessage;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        respondJson(response, 400, makeErrorResponse(null, -32600, "JSON-RPC batches are disabled on the listener."), true);
        return;
      }
      message = parsed as JsonRpcMessage;
      if (!isRequest(message) && !("result" in message) && !("error" in message)) {
        respondJson(response, 400, makeErrorResponse(null, -32600, "Invalid JSON-RPC message."), true);
        return;
      }
    } catch {
      respondJson(response, 400, makeErrorResponse(null, -32700, "Request body is not valid JSON."), true);
      return;
    }

    const headerEra = request.headers["mcp-protocol-version"] === MODERN_PROTOCOL_VERSION || protocolVersionOf(message) === MODERN_PROTOCOL_VERSION || server.protocolVersion === MODERN_PROTOCOL_VERSION
      ? MODERN_PROTOCOL_VERSION
      : undefined;
    const knownSession = existing ?? (headerEra ? await this.peekStatelessSession(serverName, clientAuthorization, headerEra) : undefined);
    const headerValidation = validateInboundRequestHeaders(
      request,
      message,
      server,
      (name) => knownSession?.transport.getToolSchema(name)
    );
    if (headerValidation) {
      respondJson(response, headerValidation.status, headerValidation.body);
      return;
    }

    const id = isRequest(message) ? message.id : undefined;
    const initializing = isRequest(message) && message.method === "initialize" && id !== undefined;
    if (existing?.shutdown.signal.aborted) {
      respondJson(response, 404, makeErrorResponse(null, -32030, "MCP session is unknown or expired."));
      return;
    }
    if ((existing || initializing) && typeof id === "string" && id.startsWith("palizade-relock-")) {
      respondJson(response, 400, makeErrorResponse(id, -32600, "The request ID uses a reserved Palizade prefix."));
      return;
    }
    if (existing && (initializing || (id !== undefined && existing.pending.has(id)))) {
      respondJson(response, 400, makeErrorResponse(id, -32600, "The request ID is already in use or the session is already initialized."));
      return;
    }

    const session = existing ?? (initializing
      ? await this.createSession(serverName, clientAuthorization, protocolVersionOf(message))
      : await this.statelessSession(serverName, clientAuthorization, protocolVersionOf(message)));
    if (!session || session.shutdown.signal.aborted) {
      respondJson(response, 503, makeErrorResponse(id, -32030, "MCP listener session capacity reached."));
      return;
    }
    session.activeRequests++;
    if (id !== undefined && existing) session.pending.add(id);
    try {
      await this.routePost(request, response, message, session, initializing);
    } finally {
      if (id !== undefined && existing) session.pending.delete(id);
      await this.releaseSession(session);
    }
  }

  private async routePost(
    request: IncomingMessage,
    response: ServerResponse,
    message: JsonRpcMessage,
    session: UpstreamSession,
    initializing: boolean
  ): Promise<void> {
    const { engine } = session.runtime;
    const id = isRequest(message) ? message.id : undefined;
    // The same stateless client credential can serve simultaneous HTTP calls with the same wire ID.
    const engineId = id !== undefined && session.statelessKey ? randomUUID() : id;
    const engineMessage = id === engineId || engineId === undefined ? message : { ...message, id: engineId };
    const abort = new AbortController();
    response.once("close", () => abort.abort());
    const signal = AbortSignal.any([abort.signal, session.shutdown.signal]);
    const output = await engine.handleClientMessage(engineMessage);
    if (signal.aborted) {
      await releasePendingRequest(engine, engineId);
      return;
    }
    const toClient: JsonRpcMessage[] = [...output.toClient];
    const isRpcRequest = isRequest(message) && message.id !== undefined;
    const wantsSse = (request.headers.accept ?? "").includes("text/event-stream");
    const bufferedIntermediate: JsonRpcMessage[] = [];
    let sseStarted = false;
    const startSse = () => {
      if (!sseStarted && !response.headersSent && !signal.aborted) {
        response.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache"
        });
        response.flushHeaders();
        sseStarted = true;
      }
    };
    let upstreamStatus: { status: number; wwwAuthenticate: string | null } | undefined;
    for (const outgoing of output.toServer) {
      const outgoingId = isRequest(outgoing) ? outgoing.id : undefined;
      const wireMessage = id !== undefined && outgoingId === engineId && engineId !== id
        ? { ...outgoing, id }
        : outgoing;
      let upstreamResponse: JsonRpcMessage | undefined;
      try {
        const { reply, status } = await this.exchange(session, wireMessage, signal, async (incoming) => {
          const routed = await engine.handleServerMessage(incoming);
          for (const item of routed.toClient) {
            if (wantsSse && isRpcRequest) {
              if (initializing) {
                bufferedIntermediate.push(item);
              } else {
                startSse();
                await writeSseEvent(response, encodeSseEvent({ data: JSON.stringify(item) }), signal);
              }
            } else if (isRequest(item) && item.id !== undefined) {
              this.securityEvent(serverNameFor(session), {
                kind: "protocol_violation",
                message: `Upstream sent server request '${item.method}' on POST SSE to a JSON-only client; cannot relay without text/event-stream.`
              });
            }
          }
          for (const item of routed.toServer) {
            await this.sendInternal(session, item, signal);
          }
        });
        upstreamStatus = status;
        upstreamResponse = reply && outgoingId !== undefined ? { ...reply, id: outgoingId } : reply;
      } catch {
        await releasePendingRequest(engine, outgoingId);
        if (!signal.aborted) {
          const failure = makeErrorResponse(id, -32030, "Upstream MCP request failed.");
          if (sseStarted) {
            await writeSseEvent(response, encodeSseEvent({ data: JSON.stringify(failure) }), signal);
            response.end();
          } else {
            respondJson(response, 502, failure);
          }
        }
        return;
      }
      if (!upstreamResponse) {
        await releasePendingRequest(engine, outgoingId);
        continue;
      }
      const routed = await engine.handleServerMessage(upstreamResponse);
      toClient.push(...routed.toClient);
      for (const item of routed.toServer) {
        await this.sendInternal(session, item, signal);
      }
      if (isRequest(outgoing) && outgoing.method === "tools/list") {
        const delivered = routed.toClient.find((item) => !isRequest(item) && item.id === outgoing.id);
        const tools = delivered && extractToolsList(delivered);
        if (tools) session.transport.updateToolSchemas(tools);
      }
    }

    let finalResponse = isRpcRequest ? toClient.find((item) => !isRequest(item) && item.id === engineId) : undefined;
    if (finalResponse && id !== undefined && engineId !== id) finalResponse = { ...finalResponse, id };
    if (upstreamStatus) {
      response.writeHead(upstreamStatus.status, {
        "Content-Type": "application/json",
        ...(upstreamStatus.wwwAuthenticate ? { "WWW-Authenticate": upstreamStatus.wwwAuthenticate } : {})
      });
      response.end(finalResponse ? JSON.stringify(finalResponse) : "");
      return;
    }
    if (!isRpcRequest) {
      response.writeHead(202).end();
      return;
    }
    if (finalResponse === undefined) {
      finalResponse = makeErrorResponse(message.id, -32603, "No response from upstream MCP server.");
    }
    if (initializing && "result" in finalResponse && !signal.aborted) {
      session.id = randomUUID();
      this.sessions.set(session.id, session);
      response.setHeader("Mcp-Session-Id", session.id);
    }

    if (wantsSse) {
      startSse();
      for (const item of bufferedIntermediate) {
        if (!await writeSseEvent(response, encodeSseEvent({ data: JSON.stringify(item) }), signal)) {
          break;
        }
      }
      await writeSseEvent(response, encodeSseEvent({ data: JSON.stringify(finalResponse) }), signal);
      response.end();
      return;
    }
    respondJson(response, 200, finalResponse);
  }

  private async exchange(
    session: UpstreamSession,
    message: JsonRpcMessage,
    signal: AbortSignal,
    onIntermediate?: (message: JsonRpcMessage) => Promise<void>
  ) {
    let reply: JsonRpcResponse | undefined;
    let status: { status: number; wwwAuthenticate: string | null } | undefined;
    const id = isRequest(message) ? message.id : undefined;
    await session.transport.send(message, authorizationHeaders(session.authorization), {
      signal,
      onStatus: (code, headers) => { status = { status: code, wwwAuthenticate: headers.get("www-authenticate") }; },
      onMessage: async (incoming) => {
        if (incoming && typeof incoming === "object" && !isRequest(incoming)) {
          if (id !== undefined && incoming.id === id) {
            if (reply !== undefined) {
              this.securityEvent(serverNameFor(session), {
                kind: "protocol_violation",
                message: `Upstream sent a duplicate response for request id '${String(incoming.id)}' on its POST stream.`
              });
              return;
            }
            reply = incoming;
            return;
          }
          this.securityEvent(serverNameFor(session), {
            kind: "protocol_violation",
            message: `Upstream sent unexpected response id '${String(incoming.id)}' on a POST stream for request id '${id === undefined ? "none" : String(id)}'.`
          });
          return;
        }
        if (onIntermediate && incoming && typeof incoming === "object") {
          await onIntermediate(incoming);
        }
      }
    });
    return { reply, status };
  }

  private async sendInternal(session: UpstreamSession, message: JsonRpcMessage, signal: AbortSignal): Promise<void> {
    let reply: JsonRpcResponse | undefined;
    try {
      ({ reply } = await this.exchange(session, message, signal));
      if (reply) {
        const routed = await session.runtime.engine.handleServerMessage(reply);
        if (isRequest(message) && message.method === "tools/list") {
          const delivered = routed.toClient.find((item) => !isRequest(item) && item.id === message.id) ?? reply;
          const tools = extractToolsList(delivered);
          if (tools) session.transport.updateToolSchemas(tools);
        }
      }
    } finally {
      if (!reply && isRequest(message)) await releasePendingRequest(session.runtime.engine, message.id);
    }
  }

  private async handleGetStream(
    request: IncomingMessage,
    response: ServerResponse,
    session: UpstreamSession
  ): Promise<void> {
    const { serverName } = session;
    const server = this.options.config.servers[serverName]!;
    if (session.transport.currentEra !== "legacy") {
      respondJson(response, 405, makeErrorResponse(null, -32030, "Upstream does not support a standalone stream."));
      return;
    }
    const upstreamHeaders = new Headers(Object.entries(resolveHeaderTemplates(server.headers ?? {})).filter(([name, value]) => (
      name.toLowerCase() !== "authorization" || !this.isListenerBearer(value)
    )));
    upstreamHeaders.set("Accept", "text/event-stream");
    const upstreamId = session.transport.legacySession;
    if (upstreamId) upstreamHeaders.set("Mcp-Session-Id", upstreamId);
    if (session.transport.legacyProtocol) upstreamHeaders.set("MCP-Protocol-Version", session.transport.legacyProtocol);
    if (session.authorization) upstreamHeaders.set("Authorization", session.authorization);
    const lastEvent = request.headers["last-event-id"];
    if (typeof lastEvent === "string") upstreamHeaders.set("Last-Event-ID", lastEvent);
    const abort = new AbortController();
    response.once("close", () => abort.abort());
    const signal = AbortSignal.any([abort.signal, session.shutdown.signal]);
    const connectTimeout = setTimeout(() => abort.abort(), this.options.config.http.requestTimeoutMs);
    let upstream: Response;
    try {
      upstream = await fetch(resolveUrlTemplate(server.url!), { method: "GET", headers: upstreamHeaders, redirect: "manual", signal });
    } catch (error) {
      if (!signal.aborted) {
        this.securityEvent(serverName, {
          kind: "upstream_http_error",
          message: `Upstream GET stream failed for '${serverName}': ${error instanceof Error ? error.message : String(error)}`
        });
      }
      if (!response.headersSent) {
        respondJson(response, 502, makeErrorResponse(null, -32030, "Upstream GET stream failed."));
      }
      return;
    } finally {
      clearTimeout(connectTimeout);
    }
    if (!upstream.ok || !upstream.body) {
      const challenge = upstream.headers.get("www-authenticate");
      if (challenge) response.setHeader("WWW-Authenticate", challenge);
      await upstream.body?.cancel();
      respondJson(response, upstream.status, makeErrorResponse(null, -32030, `Upstream GET stream returned HTTP ${upstream.status}.`));
      return;
    }
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive"
    });
    response.flushHeaders();
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
        const events: Array<{ data: string; id?: string }> = [];
        try {
          parser.feed(decoder.decode(value, { stream: true }), (event) => events.push(event));
        } catch (error) {
          this.securityEvent(serverName, {
            kind: "sse_limit_exceeded",
            message: error instanceof Error ? error.message : String(error)
          });
          break;
        }
        for (const event of events) {
          await this.routeUpstreamEvent(event, session, response, signal);
        }
      }
    } catch (error) {
      if (!signal.aborted) {
        this.securityEvent(serverName, {
          kind: "upstream_http_error",
          message: `Upstream GET stream interrupted for '${serverName}': ${error instanceof Error ? error.message : String(error)}`
        });
      }
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
      response.end();
    }
  }

  private async routeUpstreamEvent(
    event: { data: string; id?: string },
    session: UpstreamSession,
    response: ServerResponse,
    signal: AbortSignal
  ): Promise<void> {
    if (event.data === "") {
      return;
    }
    const { serverName, runtime } = session;
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(event.data) as JsonRpcMessage;
    } catch {
      this.securityEvent(serverName, {
        kind: "upstream_http_error",
        message: `Upstream SSE event carried invalid JSON for '${serverName}'.`
      });
      return;
    }
    // POST replies are correlated to their own exchange, never to a standalone GET stream.
    if (!message || typeof message !== "object" || !isRequest(message)) return;
    const routed = await runtime.engine.handleServerMessage(message);
    for (const item of routed.toClient) {
      if (!await writeSseEvent(response, encodeSseEvent({ ...(event.id === undefined ? {} : { id: event.id }), data: JSON.stringify(item) }), signal)) {
        break;
      }
    }
    for (const item of routed.toServer) {
      await this.sendInternal(session, item, signal);
    }
  }

  private async createSession(
    serverName: string,
    authorization: string | undefined,
    clientVersion: string | undefined,
    statelessKey?: string
  ): Promise<UpstreamSession | undefined> {
    if (this.active.size + this.starting >= MAX_SESSIONS) return undefined;
    const signal = this.shutdown.signal;
    this.starting++;
    let runtime: HttpListenerRuntime | undefined;
    try {
      runtime = await this.options.createRuntime(serverName);
      if (signal.aborted) {
        const abandoned = runtime;
        runtime = undefined;
        await abandoned.close?.();
        return undefined;
      }
      const server = this.options.config.servers[serverName]!;
      const transport = new HttpMcpTransport({
        serverName,
        server,
        http: this.options.config.http,
        protocolVersion: server.protocolVersion === "auto" && clientVersion === "2026-07-28" ? clientVersion : server.protocolVersion ?? "auto",
        openLegacyStream: false,
        stripAuthorization: (value) => this.isListenerBearer(value),
        onSecurityEvent: (event) => this.securityEvent(serverName, event)
      });
      const session: UpstreamSession = {
        serverName, authorization, runtime, transport, shutdown: new AbortController(),
        activeRequests: 0, pending: new Set(), lastUsed: Date.now(),
        ...(statelessKey ? { statelessKey } : {})
      };
      this.active.add(session);
      return session;
    } catch (error) {
      await runtime?.close?.();
      throw error;
    } finally {
      this.starting--;
    }
  }

  private async peekStatelessSession(
    serverName: string,
    authorization: string | undefined,
    clientVersion: string | undefined
  ): Promise<UpstreamSession | undefined> {
    const era = clientVersion === MODERN_PROTOCOL_VERSION ? clientVersion : undefined;
    const key = createHash("sha256").update(JSON.stringify([serverName, authorization, era])).digest("hex");
    return await this.stateless.get(key);
  }

  private async statelessSession(
    serverName: string,
    authorization: string | undefined,
    clientVersion: string | undefined
  ): Promise<UpstreamSession | undefined> {
    const era = clientVersion === "2026-07-28" ? clientVersion : undefined;
    const key = createHash("sha256").update(JSON.stringify([serverName, authorization, era])).digest("hex");
    const existing = this.stateless.get(key);
    if (existing) return existing;
    const starting = this.createSession(serverName, authorization, era, key);
    this.stateless.set(key, starting);
    try {
      const session = await starting;
      if (session) return session;
    } catch (error) {
      this.stateless.delete(key);
      throw error;
    }
    this.stateless.delete(key);
    return undefined;
  }

  private async releaseSession(session: UpstreamSession): Promise<void> {
    session.activeRequests--;
    session.lastUsed = Date.now();
    if ((!session.id && !session.statelessKey) || session.terminating) {
      await this.endSession(session);
    }
  }

  private async endSession(session: UpstreamSession): Promise<void> {
    if (session.id) this.sessions.delete(session.id);
    if (!session.terminating && session.statelessKey) this.stateless.delete(session.statelessKey);
    session.shutdown.abort();
    session.terminating ??= session.transport.close(authorizationHeaders(session.authorization));
    await session.terminating;
    if (session.activeRequests === 0 && this.active.delete(session)) {
      await session.runtime.close?.();
    }
  }

  private securityEvent(serverName: string, event: TransportSecurityEvent): void {
    this.options.onSecurityEvent?.({ ...event, message: `[${serverName}] ${event.message}` });
  }

  private isListenerBearer(authorization: string | undefined): boolean {
    const token = authorization?.trim().match(/^Bearer\s+(.+)$/iu)?.[1]?.trim();
    return token !== undefined && safeEqual(token, this.token);
  }
}

async function releasePendingRequest(engine: InterceptionEngine, id: JsonRpcId | undefined): Promise<void> {
  if (id !== undefined) {
    engine.releasePendingRequest(id);
  }
}

function authorizationHeaders(authorization: string | undefined): Record<string, string> | undefined {
  return authorization ? { Authorization: authorization } : undefined;
}

function serverNameFor(session: UpstreamSession): string {
  return session.serverName;
}

class PayloadTooLargeError extends Error {}

function rawMetaProtocolVersion(message: JsonRpcMessage): unknown {
  const container = isRequest(message) ? message.params : "result" in message ? message.result : undefined;
  if (container && typeof container === "object" && "_meta" in container) {
    const meta = (container as { _meta?: Record<string, unknown> })._meta;
    if (meta && typeof meta === "object" && "io.modelcontextprotocol/protocolVersion" in meta) {
      return meta["io.modelcontextprotocol/protocolVersion"];
    }
  }
  return undefined;
}

function validateInboundRequestHeaders(
  request: IncomingMessage,
  message: JsonRpcMessage,
  server: ServerConfig,
  getToolSchema: (name: string) => McpTool | undefined
): { status: number; body: JsonRpcMessage } | undefined {
  const id = isRequest(message) ? message.id : undefined;
  const rawHeaderVersion = request.headers["mcp-protocol-version"];
  if (Array.isArray(rawHeaderVersion)) {
    return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Duplicate MCP-Protocol-Version header.") };
  }
  const headerVersion = typeof rawHeaderVersion === "string" ? rawHeaderVersion : undefined;
  const rawBodyVersion = rawMetaProtocolVersion(message);
  if (rawBodyVersion !== undefined && typeof rawBodyVersion !== "string") {
    return { status: 400, body: makeErrorResponse(id, -32000, "UnsupportedProtocolVersionError: Invalid protocolVersion type in _meta.") };
  }
  const bodyVersion = protocolVersionOf(message);

  if (headerVersion !== undefined && !SUPPORTED_PROTOCOL_VERSIONS.has(headerVersion)) {
    return { status: 400, body: makeErrorResponse(id, -32000, `UnsupportedProtocolVersionError: Unsupported MCP-Protocol-Version '${headerVersion}'.`) };
  }
  if (bodyVersion !== undefined && !SUPPORTED_PROTOCOL_VERSIONS.has(bodyVersion)) {
    return { status: 400, body: makeErrorResponse(id, -32000, `UnsupportedProtocolVersionError: Unsupported protocol version '${bodyVersion}'.`) };
  }
  if (headerVersion !== undefined && bodyVersion !== undefined && headerVersion !== bodyVersion) {
    return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: MCP-Protocol-Version header '${headerVersion}' does not match body '${bodyVersion}'.`) };
  }

  const isModern = bodyVersion === MODERN_PROTOCOL_VERSION ||
    headerVersion === MODERN_PROTOCOL_VERSION ||
    server.protocolVersion === MODERN_PROTOCOL_VERSION;

  const rawHeaderMethod = request.headers["mcp-method"];
  if (Array.isArray(rawHeaderMethod)) {
    return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Duplicate Mcp-Method header.") };
  }
  const headerMethod = typeof rawHeaderMethod === "string" ? rawHeaderMethod : undefined;

  const rawHeaderName = request.headers["mcp-name"];
  if (Array.isArray(rawHeaderName)) {
    return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Duplicate Mcp-Name header.") };
  }
  const headerName = typeof rawHeaderName === "string" ? rawHeaderName : undefined;

  if (!isModern) {
    if (headerMethod !== undefined && (!isRequest(message) || headerMethod !== message.method)) {
      return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Mcp-Method header does not match body method.") };
    }
    if (headerName !== undefined && isRequest(message)) {
      const params = (message.params ?? {}) as Record<string, unknown>;
      const target = message.method === "resources/read" ? params.uri : params.name;
      const decoded = decodeHeaderValue(headerName);
      if (typeof target !== "string" || decoded === undefined || decoded !== target) {
        return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Mcp-Name header does not match body target.") };
      }
    }
    return undefined;
  }

  if (headerVersion !== MODERN_PROTOCOL_VERSION) {
    return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: MCP-Protocol-Version header must be '2026-07-28' for a 2026-07-28 request.") };
  }
  if (isRequest(message) && message.id !== undefined && bodyVersion !== MODERN_PROTOCOL_VERSION) {
    return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Body _meta['io.modelcontextprotocol/protocolVersion'] is required for a 2026-07-28 request.") };
  }
  if (isRequest(message)) {
    if (headerMethod === undefined) {
      return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Mcp-Method header is missing.") };
    }
    if (headerMethod !== message.method) {
      return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Mcp-Method header '${headerMethod}' does not match body method '${message.method}'.`) };
    }
    const params = (message.params && typeof message.params === "object" ? message.params : {}) as Record<string, unknown>;
    const expectedName = message.method === "resources/read"
      ? (typeof params.uri === "string" ? params.uri : undefined)
      : (message.method === "tools/call" || message.method === "prompts/get")
        ? (typeof params.name === "string" ? params.name : undefined)
        : undefined;
    if (message.method === "tools/call" || message.method === "resources/read" || message.method === "prompts/get") {
      if (headerName === undefined) {
        return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Mcp-Name header is missing for '${message.method}'.`) };
      }
      const decoded = decodeHeaderValue(headerName);
      if (expectedName === undefined || decoded === undefined || decoded !== expectedName) {
        return { status: 400, body: makeErrorResponse(id, -32020, "HeaderMismatch: Mcp-Name header does not match body target.") };
      }
    } else if (headerName !== undefined) {
      return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Unexpected Mcp-Name header for method '${message.method}'.`) };
    }

    const paramHeaderEntries = Object.entries(request.headers).filter(([key]) => key.startsWith("mcp-param-"));
    for (const [key, rawValue] of paramHeaderEntries) {
      if (typeof rawValue !== "string" || decodeHeaderValue(rawValue) === undefined) {
        return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Invalid '${key}' parameter header.`) };
      }
    }
    if (message.method === "tools/call" && typeof params.name === "string" && paramHeaderEntries.length > 0) {
      const toolSchema = getToolSchema(params.name);
      if (toolSchema) {
        const annotations = collectXMcpHeaderAnnotations(toolSchema);
        const args = (params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments))
          ? params.arguments as Record<string, unknown>
          : {};
        for (const annotation of annotations) {
          const rawParam = request.headers[`mcp-param-${annotation.name.toLowerCase()}`];
          if (typeof rawParam !== "string") continue;
          const decoded = decodeHeaderValue(rawParam);
          const bodyValue = lookupPath(args, annotation.path);
          if (bodyValue === undefined || bodyValue === null) {
            return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Mcp-Param-${annotation.name} present for absent argument.`) };
          }
          const expected = typeof bodyValue === "boolean" ? (bodyValue ? "true" : "false") : String(bodyValue);
          if (decoded !== expected) {
            return { status: 400, body: makeErrorResponse(id, -32020, `HeaderMismatch: Mcp-Param-${annotation.name} does not match argument value.`) };
          }
        }
      }
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

function respondJson(response: ServerResponse, status: number, body: JsonRpcMessage, closeConnection = false): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  response.writeHead(status, {
    "Content-Type": "application/json",
    ...(closeConnection ? { Connection: "close" } : {})
  });
  response.end(JSON.stringify(body));
}

async function writeSseEvent(response: ServerResponse, chunk: string, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted || response.writableEnded || response.destroyed) {
    return false;
  }
  if (response.writableLength > MAX_SSE_BUFFER_BYTES) {
    response.destroy();
    return false;
  }
  if (response.write(chunk)) {
    return true;
  }
  await new Promise<void>((resolve) => {
    const done = () => {
      response.off("drain", done);
      response.off("close", done);
      signal.removeEventListener("abort", done);
      resolve();
    };
    response.once("drain", done);
    response.once("close", done);
    signal.addEventListener("abort", done, { once: true });
  });
  return !signal.aborted && !response.writableEnded && !response.destroyed;
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
  const contentLengthHeader = request.headers["content-length"];
  if (contentLengthHeader !== undefined) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new PayloadTooLargeError(`Request body exceeded ${maxBytes} bytes.`);
    }
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) {
      throw new PayloadTooLargeError(`Request body exceeded ${maxBytes} bytes.`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
