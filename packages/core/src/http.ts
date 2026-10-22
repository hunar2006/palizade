import { EventEmitter } from "node:events";
import { expandEnvTemplates } from "./env-templates.js";
import { isRequest, isSuccess, type JsonRpcId, type JsonRpcMessage, type McpTool } from "./mcp.js";
import type { PalizadeConfig, ServerConfig } from "./config.js";
import type { InterceptionEngine } from "./interceptor.js";
import { LineJsonRpcPeer } from "./stdio.js";

export type HttpEra = "2026-07-28" | "legacy";

export interface TransportSecurityEvent {
  kind: "protocol_violation" | "cross_origin_redirect_refused" | "header_mismatch" | "sse_limit_exceeded" | "upstream_http_error" | "token_never_forwarded" | "invalid_tool_schema" | "concurrency_limit";
  message: string;
  detail?: unknown;
}

export interface HttpMcpTransportOptions {
  serverName: string;
  server: ServerConfig;
  http: PalizadeConfig["http"];
  protocolVersion?: "auto" | "2026-07-28" | "2025-11-25";
  env?: NodeJS.ProcessEnv;
  onSecurityEvent?: (event: TransportSecurityEvent) => void;
  requestHeaders?: Record<string, string>;
}

const PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion";
const BASE64_SENTINEL_PREFIX = "=?base64?";
const BASE64_SENTINEL_SUFFIX = "?=";
const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export function isAsciiSafeHeaderValue(value: string): boolean {
  if (/^[\x20\x09\x21-\x7E]*$/u.test(value)) {
    const trimmed = value.trim();
    if (value === trimmed) {
      return !(value.startsWith(BASE64_SENTINEL_PREFIX) && value.endsWith(BASE64_SENTINEL_SUFFIX));
    }
  }
  return false;
}

export function encodeHeaderValue(value: string): string {
  if (isAsciiSafeHeaderValue(value)) {
    return value;
  }
  return `${BASE64_SENTINEL_PREFIX}${Buffer.from(value, "utf8").toString("base64")}${BASE64_SENTINEL_SUFFIX}`;
}

export function decodeHeaderValue(value: string): string | undefined {
  if (value.startsWith(BASE64_SENTINEL_PREFIX) && value.endsWith(BASE64_SENTINEL_SUFFIX)) {
    try {
      return Buffer.from(value.slice(BASE64_SENTINEL_PREFIX.length, -BASE64_SENTINEL_SUFFIX.length), "base64").toString("utf8");
    } catch {
      return undefined;
    }
  }
  return value;
}

export function protocolVersionOf(message: JsonRpcMessage): string | undefined {
  if (!isRequest(message) && !("result" in message)) {
    return undefined;
  }
  const container = isRequest(message) ? message.params : (message as { result: unknown }).result;
  if (container && typeof container === "object" && "_meta" in container) {
    const meta = (container as { _meta?: Record<string, unknown> })._meta;
    const version = meta?.[PROTOCOL_VERSION_META_KEY];
    if (typeof version === "string") {
      return version;
    }
  }
  return undefined;
}

/** Expands `${NAME}` in a server url; an unset variable is an error, since the url would be wrong. */
export function resolveUrlTemplate(url: string, env: NodeJS.ProcessEnv = process.env): string {
  const expanded = expandEnvTemplates(url, env);
  if (expanded.missing.length > 0) {
    throw new Error(`Server url needs environment variables that are not set: ${expanded.missing.join(", ")}`);
  }
  return expanded.value;
}

export function resolveHeaderTemplates(headers: Record<string, string>, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const expanded = expandEnvTemplates(value, env);
    // A header whose variable is unset is dropped rather than sent with a literal placeholder.
    if (expanded.missing.length > 0) {
      continue;
    }
    resolved[name] = expanded.value;
  }
  return resolved;
}

export class SseParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SseParseError";
  }
}

export interface SseEvent {
  event?: string;
  data: string;
  id?: string;
}

export class SseParser {
  private lineBuffer = "";
  private eventName: string | undefined;
  private id: string | undefined;
  private dataLines: string[] = [];
  private eventBytes = 0;

  constructor(private readonly limits: { maxLineBytes: number; maxEventBytes: number }) {}

  feed(chunk: string, onEvent: (event: SseEvent) => void): void {
    this.lineBuffer += chunk;
    let newline: number;
    while ((newline = this.lineBuffer.indexOf("\n")) !== -1) {
      let line = this.lineBuffer.slice(0, newline);
      this.lineBuffer = this.lineBuffer.slice(newline + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      if (Buffer.byteLength(line, "utf8") > this.limits.maxLineBytes) {
        throw new SseParseError(`SSE line exceeded ${this.limits.maxLineBytes} bytes`);
      }
      if (line === "") {
        const data = this.dataLines.join("\n");
        const size = Buffer.byteLength(data, "utf8") + (this.id ? Buffer.byteLength(this.id, "utf8") : 0);
        this.eventBytes += size;
        if (this.eventBytes > this.limits.maxEventBytes) {
          throw new SseParseError(`SSE event exceeded ${this.limits.maxEventBytes} bytes`);
        }
        if (data.length > 0) {
          onEvent({
            ...(this.eventName !== undefined ? { event: this.eventName } : {}),
            data,
            ...(this.id !== undefined ? { id: this.id } : {})
          });
        }
        this.eventName = undefined;
        this.id = undefined;
        this.dataLines = [];
        this.eventBytes = 0;
        continue;
      }
      if (line.startsWith(":")) {
        continue;
      }
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      let value = colon === -1 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) {
        value = value.slice(1);
      }
      if (field === "data") {
        this.dataLines.push(value);
      } else if (field === "event") {
        this.eventName = value;
      } else if (field === "id") {
        this.id = value;
      }
    }
  }
}

export function encodeSseEvent(event: SseEvent): string {
  const parts: string[] = [];
  if (event.id !== undefined) {
    parts.push(`id: ${event.id}`);
  }
  if (event.event !== undefined) {
    parts.push(`event: ${event.event}`);
  }
  for (const line of event.data.split("\n")) {
    parts.push(`data: ${line}`);
  }
  return `${parts.join("\n")}\n\n`;
}

function isModernMessage(message: JsonRpcMessage): boolean {
  if (isRequest(message)) {
    return protocolVersionOf(message) !== undefined;
  }
  if ("result" in message) {
    return protocolVersionOf(message) !== undefined;
  }
  return false;
}

function isModernJsonRpcErrorBody(body: unknown): boolean {
  if (typeof body !== "object" || body === null) {
    return false;
  }
  const record = body as Record<string, unknown>;
  return record.jsonrpc === "2.0" && typeof record.error === "object" && record.error !== null;
}

function isModernRejectionBody(body: unknown): boolean {
  if (!isModernJsonRpcErrorBody(body)) {
    return false;
  }
  const record = body as Record<string, unknown>;
  const error = record.error as Record<string, unknown>;
  const code = error.code;
  if (typeof code === "number" && (code === -32601 || code === -32020 || code === -32000 || code === -32001)) {
    return true;
  }
  const protocolVersion = protocolVersionOf({ jsonrpc: "2.0", id: 0, result: record.error } as JsonRpcMessage);
  return protocolVersion !== undefined;
}

class RedirectRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedirectRefusedError";
  }
}

export class HttpMcpTransport extends EventEmitter {
  private era: HttpEra = "legacy";
  private readonly url: string;
  private legacySessionId: string | undefined;
  private lastEventId: string | undefined;
  private legacyStreamAbort: AbortController | undefined;
  private readonly toolSchemas = new Map<string, McpTool>();
  private activeStreams = 0;
  private closed = false;
  private readonly pendingWaiters = new Set<string>();
  private readonly env: NodeJS.ProcessEnv;

  constructor(private readonly options: HttpMcpTransportOptions) {
    super();
    const server = options.server;
    if (!server.url) {
      throw new Error(`Server '${options.serverName}' has no url; cannot use the HTTP transport.`);
    }
    this.env = options.env ?? process.env;
    this.url = resolveUrlTemplate(server.url, this.env);
    if (options.protocolVersion === "2026-07-28") {
      this.era = "2026-07-28";
    } else if (options.protocolVersion === "2025-11-25") {
      this.era = "legacy";
    }
  }

  get currentEra(): HttpEra {
    return this.era;
  }

  get legacySession(): string | undefined {
    return this.legacySessionId;
  }

  async send(message: JsonRpcMessage, requestHeaders?: Record<string, string>): Promise<void> {
    if (this.closed) {
      throw new Error(`Upstream HTTP transport for '${this.options.serverName}' is closed.`);
    }
    await this.acquire();
    try {
      if (this.era === "2026-07-28") {
        await this.sendModern(message, requestHeaders);
      } else {
        await this.sendLegacy(message, requestHeaders);
      }
    } finally {
      this.release();
    }
  }

  updateToolSchemas(tools: McpTool[]): void {
    for (const tool of tools) {
      if (tool?.name) {
        this.toolSchemas.set(tool.name, tool);
      }
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.legacyStreamAbort?.abort();
    if (this.era === "legacy" && this.legacySessionId) {
      try {
        await fetch(this.url, {
          method: "DELETE",
          headers: {
            ...this.resolvedHeaders({ "Mcp-Session-Id": this.legacySessionId }),
            "Mcp-Session-Id": this.legacySessionId
          },
          redirect: "manual"
        });
      } catch {
        // best effort session termination
      }
    }
    for (const key of this.pendingWaiters) {
      this.emit("message", {
        jsonrpc: "2.0",
        id: key === "null" ? null : key,
        error: { code: -32030, message: `Upstream transport for '${this.options.serverName}' closed.` }
      });
    }
    this.pendingWaiters.clear();
  }

  waitForResponse(id: JsonRpcId, timeoutMs: number): Promise<JsonRpcMessage> {
    return new Promise((resolve, reject) => {
      const key = String(id);
      const onMessage = (message: JsonRpcMessage): void => {
        if (isRequest(message) || String((message as { id: JsonRpcId }).id) !== key) {
          return;
        }
        clearTimeout(timer);
        this.removeListener("message", onMessage);
        this.pendingWaiters.delete(key);
        resolve(message);
      };
      const timer = setTimeout(() => {
        this.removeListener("message", onMessage);
        this.pendingWaiters.delete(key);
        reject(new Error(`Timed out waiting for upstream response id=${key}`));
      }, timeoutMs);
      this.on("message", onMessage);
      this.pendingWaiters.add(key);
    });
  }

  private async sendModern(message: JsonRpcMessage, requestHeaders?: Record<string, string>): Promise<void> {
    const headers = this.resolvedHeaders(this.modernHeadersFor(message), requestHeaders);
    const response = await this.requestWithRedirectGuard("POST", headers, JSON.stringify(message));
    if (response.status === 202) {
      await discardBody(response);
      return;
    }
    await this.handleModernResponse(response, message);
  }

  private async sendLegacy(message: JsonRpcMessage, requestHeaders?: Record<string, string>): Promise<void> {
    const headers = this.resolvedHeaders({
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(this.legacySessionId ? { "Mcp-Session-Id": this.legacySessionId } : {})
    }, requestHeaders);
    const response = await this.requestWithRedirectGuard("POST", headers, JSON.stringify(message));
    const sessionId = response.headers.get("Mcp-Session-Id");
    if (sessionId) {
      this.legacySessionId = sessionId;
      this.era = "legacy";
    }
    if (response.status === 404 || response.status === 400 || response.status === 405) {
      this.emit("upstreamStatus", response.status, Object.fromEntries(response.headers.entries()));
      const body = parseJsonBody(await readBodyBounded(response, this.options.http.maxBodyBytes));
      if (isModernRejectionBody(body)) {
        if (isRequest(message) && message.method === "initialize" && message.id !== undefined) {
          this.era = "2026-07-28";
          this.emit("message", makeSyntheticInitializeResponse(message.id, this.options.serverName));
          return;
        }
        this.emitUpstreamError(message, response.status, body);
        return;
      }
      this.emitUpstreamError(message, response.status, body);
      return;
    }
    if (!response.ok) {
      this.emit("upstreamStatus", response.status, Object.fromEntries(response.headers.entries()));
      const body = await readBodyBounded(response, this.options.http.maxBodyBytes);
      this.emitUpstreamError(message, response.status, body);
      return;
    }
    if (isRequest(message) && message.method === "initialize" && !this.legacyStreamAbort) {
      this.openLegacyStream();
    }
    const body = await readBodyBounded(response, this.options.http.maxBodyBytes);
    if (typeof body === "string" && body.trim().length > 0) {
      try {
        this.emitInbound(JSON.parse(body) as JsonRpcMessage, "json");
      } catch {
        this.securityEvent({
          kind: "upstream_http_error",
          message: `Upstream returned invalid JSON body for '${this.options.serverName}'.`
        });
      }
    }
  }

  private async handleModernResponse(response: Response, sent: JsonRpcMessage): Promise<void> {
    if (!response.ok) {
      this.emit("upstreamStatus", response.status, Object.fromEntries(response.headers.entries()));
      const body = parseJsonBody(await readBodyBounded(response, this.options.http.maxBodyBytes));
      if (body !== undefined && isModernJsonRpcErrorBody(body)) {
        this.emitInbound(body as unknown as JsonRpcMessage, "json");
        return;
      }
      this.emitUpstreamError(sent, response.status, body);
      return;
    }
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("text/event-stream")) {
      await this.consumeModernSse(response);
      return;
    }
    const body = await readBodyBounded(response, this.options.http.maxBodyBytes);
    if (body === undefined || (typeof body === "string" && body.trim() === "")) {
      return;
    }
    let parsed: JsonRpcMessage;
    try {
      parsed = JSON.parse(String(body)) as JsonRpcMessage;
    } catch {
      this.securityEvent({
        kind: "upstream_http_error",
        message: `Upstream returned invalid JSON body for '${this.options.serverName}'.`
      });
      return;
    }
    if (isRequest(parsed)) {
      this.securityEvent({
        kind: "protocol_violation",
        message: `Upstream pushed a JSON-RPC request on a POST response in the 2026-07-28 era; the spec forbids it. Message dropped.`,
        detail: { method: parsed.method }
      });
      return;
    }
    this.validateModernResponseHeaders(response, parsed);
    this.emitInbound(parsed, "json");
  }

  private async consumeModernSse(response: Response): Promise<void> {
    if (!response.body) {
      return;
    }
    const parser = new SseParser({
      maxLineBytes: this.options.http.maxSseLineBytes,
      maxEventBytes: this.options.http.maxSseEventBytes
    });
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        const messages: JsonRpcMessage[] = [];
        try {
          parser.feed(decoder.decode(value, { stream: true }), (event) => {
            try {
              messages.push(JSON.parse(event.data) as JsonRpcMessage);
            } catch {
              this.securityEvent({
                kind: "upstream_http_error",
                message: `Upstream SSE event carried invalid JSON for '${this.options.serverName}'.`
              });
            }
          });
        } catch (error) {
          this.securityEvent({
            kind: "sse_limit_exceeded",
            message: error instanceof Error ? error.message : String(error)
          });
          break;
        }
        for (const message of messages) {
          if ("method" in message && "id" in message) {
            this.securityEvent({
              kind: "protocol_violation",
              message: `Upstream pushed a JSON-RPC request on an SSE stream in the 2026-07-28 era; the spec forbids it. Message dropped.`,
              detail: { method: message.method }
            });
          } else {
            this.validateModernResponseHeaders(response, message);
            this.emitInbound(message, "sse");
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  private validateModernResponseHeaders(response: Response, message: JsonRpcMessage): void {
    const headerVersion = response.headers.get("MCP-Protocol-Version");
    const bodyVersion = protocolVersionOf(message);
    if (headerVersion && bodyVersion && headerVersion !== bodyVersion) {
      this.securityEvent({
        kind: "header_mismatch",
        message: `Upstream MCP-Protocol-Version header '${headerVersion}' does not match body protocol version '${bodyVersion}'; response rejected.`
      });
      return;
    }
    const headerMethod = response.headers.get("Mcp-Method");
    if (headerMethod && "method" in message && headerMethod !== (message as { method: string }).method) {
      this.securityEvent({
        kind: "header_mismatch",
        message: `Upstream Mcp-Method header '${headerMethod}' does not match body method '${(message as { method: string }).method}'; response rejected.`
      });
    }
  }

  private openLegacyStream(): void {
    if (this.legacyStreamAbort) {
      return;
    }
    this.legacyStreamAbort = new AbortController();
    const headers = this.resolvedHeaders({
      Accept: "text/event-stream",
      "Mcp-Session-Id": this.legacySessionId ?? "",
      ...(this.lastEventId ? { "Last-Event-ID": this.lastEventId } : {})
    });
    void this.consumeLegacyStream(headers);
  }

  private async consumeLegacyStream(headers: Record<string, string>): Promise<void> {
    const signal = this.legacyStreamAbort?.signal;
    try {
      const response = await fetch(this.url, {
        method: "GET",
        headers,
        redirect: "manual",
        ...(signal ? { signal } : {})
      });
      if (!response.ok) {
        this.securityEvent({
          kind: "upstream_http_error",
          message: `Legacy GET SSE stream failed with HTTP ${response.status} for '${this.options.serverName}'.`
        });
        return;
      }
      if (!response.body) {
        return;
      }
      const parser = new SseParser({
        maxLineBytes: this.options.http.maxSseLineBytes,
        maxEventBytes: this.options.http.maxSseEventBytes
      });
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        try {
          parser.feed(decoder.decode(value, { stream: true }), (event) => {
            if (event.id) {
              this.lastEventId = event.id;
            }
            try {
              const message = JSON.parse(event.data) as JsonRpcMessage;
              this.emitInbound(message, "sse");
            } catch {
              this.securityEvent({
                kind: "upstream_http_error",
                message: `Legacy SSE event carried invalid JSON for '${this.options.serverName}'.`
              });
            }
          });
        } catch (error) {
          this.securityEvent({
            kind: "sse_limit_exceeded",
            message: error instanceof Error ? error.message : String(error)
          });
          break;
        }
      }
    } catch (error) {
      if (!this.closed && !this.isAbortError(error)) {
        this.securityEvent({
          kind: "upstream_http_error",
          message: `Legacy GET SSE stream failed for '${this.options.serverName}': ${error instanceof Error ? error.message : String(error)}`
        });
      }
    }
  }

  private modernHeadersFor(message: JsonRpcMessage): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    };
    const version = protocolVersionOf(message) ?? "2026-07-28";
    headers["MCP-Protocol-Version"] = version;
    if (isRequest(message)) {
      headers["Mcp-Method"] = message.method;
      const params = (message.params ?? {}) as Record<string, unknown>;
      if (message.method === "tools/call" && typeof params.name === "string") {
        headers["Mcp-Name"] = encodeHeaderValue(params.name);
        this.appendMcpParamHeaders(headers, params.name, params.arguments);
      } else if ((message.method === "resources/read" || message.method === "prompts/get") && typeof params.uri === "string") {
        headers["Mcp-Name"] = encodeHeaderValue(params.uri);
      }
    }
    return headers;
  }

  private appendMcpParamHeaders(headers: Record<string, string>, toolName: string, args: unknown): void {
    const tool = this.toolSchemas.get(toolName);
    const annotations = collectXMcpHeaderAnnotations(tool);
    if (annotations.length === 0 || typeof args !== "object" || args === null) {
      return;
    }
    const record = args as Record<string, unknown>;
    for (const annotation of annotations) {
      if (!isValidMcpHeaderName(annotation.name)) {
        this.securityEvent({
          kind: "invalid_tool_schema",
          message: `Tool '${toolName}' declares invalid x-mcp-header name; header omitted.`
        });
        continue;
      }
      const value = lookupPath(record, annotation.path);
      if (value === undefined || value === null) {
        continue;
      }
      const stringified = typeof value === "boolean" ? (value ? "true" : "false") : String(value);
      headers[`Mcp-Param-${annotation.name}`] = encodeHeaderValue(stringified);
    }
  }

  private resolvedHeaders(extra: Record<string, string>, perCall?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(resolveHeaderTemplates(this.options.server.headers ?? {}, this.env))) {
      headers[name] = value;
    }
    for (const [name, value] of Object.entries(this.options.requestHeaders ?? {})) {
      if (name.toLowerCase() === "authorization" && !hasHeader(headers, "authorization")) {
        headers.Authorization = value;
      } else if (name.toLowerCase() !== "authorization") {
        headers[name] = value;
      }
    }
    for (const [name, value] of Object.entries(perCall ?? {})) {
      if (name.toLowerCase() === "authorization") {
        headers.Authorization = value;
      } else {
        headers[name] = value;
      }
    }
    for (const [name, value] of Object.entries(extra)) {
      headers[name] = value;
    }
    return headers;
  }

  private async requestWithRedirectGuard(method: "POST" | "GET" | "DELETE", headers: Record<string, string>, body?: string): Promise<Response> {
    const hasAuthorization = Object.keys(headers).some((name) => name.toLowerCase() === "authorization");
    const origin = new URL(this.url).origin;
    let currentUrl = this.url;
    let redirects = 0;
    while (true) {
      const response = await fetch(currentUrl, {
        method,
        headers,
        ...(body !== undefined ? { body } : {}),
        redirect: "manual",
        signal: AbortSignal.timeout(this.options.http.requestTimeoutMs)
      });
      const location = response.headers.get("location");
      const isRedirect = response.status >= 300 && response.status < 400 && location;
      if (!isRedirect) {
        return response;
      }
      if (hasAuthorization) {
        this.securityEvent({
          kind: "token_never_forwarded",
          message: `Refused to follow redirect for '${this.options.serverName}': Authorization is never forwarded to a redirect target.`
        });
        throw new RedirectRefusedError(`Refused redirect for '${this.options.serverName}' while Authorization is set; failing closed.`);
      }
      redirects += 1;
      if (redirects > this.options.http.maxRedirects) {
        throw new RedirectRefusedError(`Too many redirects for '${this.options.serverName}'.`);
      }
      const next = new URL(location, currentUrl);
      if (next.origin !== origin) {
        this.securityEvent({
          kind: "cross_origin_redirect_refused",
          message: `Refused cross-origin redirect from '${origin}' to '${next.origin}' for '${this.options.serverName}'.`
        });
        throw new RedirectRefusedError(`Cross-origin redirect refused for '${this.options.serverName}'.`);
      }
      await discardBody(response);
      currentUrl = next.toString();
      if (method === "POST" && (response.status === 303)) {
        method = "GET";
        body = undefined;
      }
    }
  }

  private emitInbound(message: JsonRpcMessage, via: "json" | "sse"): void {
    this.emit("message", message, via);
  }

  private emitUpstreamError(sent: JsonRpcMessage, status: number, body: unknown): void {
    const id = isRequest(sent) ? sent.id : undefined;
    const detail = body === undefined
      ? undefined
      : typeof body === "string"
        ? body.slice(0, 500)
        : JSON.stringify(body).slice(0, 500);
    if (id !== undefined) {
      this.emitInbound({
        jsonrpc: "2.0",
        id,
        error: {
          code: -32030,
          message: `Upstream MCP endpoint returned HTTP ${status}${detail ? `: ${detail}` : ""}.`
        }
      }, "json");
    } else {
      this.securityEvent({
        kind: "upstream_http_error",
        message: `Upstream MCP endpoint returned HTTP ${status} for a notification.`,
        detail
      });
    }
  }

  private async acquire(): Promise<void> {
    while (this.activeStreams >= this.options.http.maxConcurrentStreams) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    this.activeStreams += 1;
  }

  private release(): void {
    this.activeStreams -= 1;
  }

  private securityEvent(event: TransportSecurityEvent): void {
    this.emit("securityEvent", event);
    this.options.onSecurityEvent?.(event);
  }

  private isAbortError(error: unknown): boolean {
    return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
  }
}

async function readBodyBounded(response: Response, maxBytes: number): Promise<string | undefined> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    throw new Error(`Upstream response body exceeded ${maxBytes} bytes`);
  }
  return text;
}

function parseJsonBody(text: string | undefined): unknown {
  if (text === undefined || text.trim() === "") {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function discardBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}

function makeSyntheticInitializeResponse(id: JsonRpcId, serverName: string): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      protocolVersion: "2026-07-28",
      capabilities: {},
      serverInfo: { name: serverName, version: "palizade-proxy" },
      _meta: { [PROTOCOL_VERSION_META_KEY]: "2026-07-28" }
    }
  };
}

interface McpHeaderAnnotation {
  name: string;
  path: string[];
}

function collectXMcpHeaderAnnotations(tool: McpTool | undefined): McpHeaderAnnotation[] {
  if (!tool?.inputSchema) {
    return [];
  }
  const output: McpHeaderAnnotation[] = [];
  walkSchemaProperties(tool.inputSchema, [], output);
  return output;
}

function walkSchemaProperties(schema: unknown, path: string[], output: McpHeaderAnnotation[]): void {
  if (!schema || typeof schema !== "object") {
    return;
  }
  const record = schema as Record<string, unknown>;
  const properties = record.properties;
  if (properties && typeof properties === "object") {
    for (const [key, child] of Object.entries(properties)) {
      if (child && typeof child === "object" && "x-mcp-header" in (child as Record<string, unknown>)) {
        const annotation = (child as Record<string, unknown>)["x-mcp-header"];
        if (typeof annotation === "string") {
          output.push({ name: annotation, path: [...path, key] });
        }
      }
      walkSchemaProperties(child, [...path, key], output);
    }
  }
}

function isValidMcpHeaderName(name: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(name) && !/[\r\n]/u.test(name);
}

function hasHeader(headers: Record<string, string>, lowerName: string): boolean {
  return Object.keys(headers).some((name) => name.toLowerCase() === lowerName);
}

function lookupPath(record: Record<string, unknown>, path: string[]): unknown {
  let current: unknown = record;
  for (const key of path) {
    if (!current || typeof current !== "object" || !(key in current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

export interface HttpBridgeProxyOptions {
  serverName: string;
  server: ServerConfig;
  config: PalizadeConfig;
  engine: InterceptionEngine;
  onSecurityEvent?: (event: TransportSecurityEvent) => void;
}

export class HttpBridgeProxy {
  private readonly upstream: HttpMcpTransport;

  constructor(private readonly options: HttpBridgeProxyOptions) {
    this.upstream = new HttpMcpTransport({
      serverName: options.serverName,
      server: options.server,
      http: options.config.http,
      protocolVersion: options.server.protocolVersion ?? "auto",
      onSecurityEvent: (event) => options.onSecurityEvent?.(event)
    });
    this.upstream.on("securityEvent", (event: TransportSecurityEvent) => options.onSecurityEvent?.(event));
  }

  async run(): Promise<void> {
    const engine = this.options.engine;
    const client = new LineJsonRpcPeer(process.stdin, process.stdout, {
      maxMessageBytes: this.options.config.transport.maxMessageBytes,
      maxBufferedBytes: this.options.config.transport.maxBufferedBytes,
      allowBatches: this.options.config.transport.allowBatches,
      allowContentLength: this.options.config.transport.allowContentLength
    });
    const pendingMethods = new Map<string, string>();
    let queue = Promise.resolve();

    client.on("message", (envelope: JsonRpcMessage | JsonRpcMessage[]) => {
      queue = queue.then(async () => {
        const messages = Array.isArray(envelope) ? envelope : [envelope];
        const toClient: JsonRpcMessage[] = [];
        for (const message of messages) {
          if (isRequest(message) && message.id !== undefined) {
            pendingMethods.set(String(message.id), message.method);
          }
          const output = await engine.handleClientMessage(message);
          for (const item of output.toClient) {
            toClient.push(item);
          }
          for (const item of output.toServer) {
            await this.upstream.send(item);
          }
        }
        for (const item of toClient) {
          client.send(item);
        }
      }).catch((error: unknown) => {
        process.stderr.write(`[palizade:${this.options.serverName}] client message error: ${formatError(error)}\n`);
      });
    });

    this.upstream.on("message", (message: JsonRpcMessage) => {
      queue = queue.then(async () => {
        const output = await engine.handleServerMessage(message);
        for (const item of output.toClient) {
          if (isSuccess(item) && pendingMethods.get(String(item.id)) === "tools/list") {
            const tools = (item.result as { tools?: McpTool[] }).tools;
            if (Array.isArray(tools)) {
              this.upstream.updateToolSchemas(tools);
            }
          }
          client.send(item);
        }
        for (const item of output.toServer) {
          await this.upstream.send(item);
        }
      }).catch((error: unknown) => {
        process.stderr.write(`[palizade:${this.options.serverName}] upstream message error: ${formatError(error)}\n`);
      });
    });

    client.on("end", () => {
      queue.finally(() => this.upstream.close()).catch(() => void this.upstream.close());
    });

    this.upstream.on("error", (error: unknown) => {
      process.stderr.write(`[palizade:${this.options.serverName}] upstream error: ${formatError(error)}\n`);
    });
  }
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isLocalhostOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return LOCALHOST_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

export async function collectToolsFromHttpServer(server: ServerConfig, limits: PalizadeConfig["http"], timeoutMs = 5_000): Promise<McpTool[]> {
  if (!server.url) {
    throw new Error("collectToolsFromHttpServer requires a server with a url.");
  }
  const request = {
    jsonrpc: "2.0",
    id: "palizade-lock-probe",
    method: "tools/list",
    params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
  } as JsonRpcMessage;
  const attempt = await fetch(resolveUrlTemplate(server.url), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": "tools/list",
      ...resolveHeaderTemplates(server.headers ?? {})
    },
    body: JSON.stringify(request),
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (attempt.ok) {
    const body = await readBodyBounded(attempt, limits.maxBodyBytes);
    const parsed = JSON.parse(body ?? "null") as JsonRpcMessage;
    if ("result" in parsed) {
      const tools = (parsed.result as { tools?: unknown }).tools;
      return Array.isArray(tools) ? (tools as McpTool[]) : [];
    }
    return [];
  }
  const transport = new HttpMcpTransport({ serverName: "lock-probe", server, http: limits });
  const responsePromise = transport.waitForResponse("palizade-lock-probe-2", timeoutMs);
  await transport.send({
    jsonrpc: "2.0",
    id: "palizade-lock-probe-2",
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "palizade", version: "lock-probe" }
    }
  });
  const initializeResponse = await responsePromise;
  if ("error" in initializeResponse) {
    await transport.close();
    throw new Error(`tools/list over HTTP failed: ${initializeResponse.error.message}`);
  }
  const toolsPromise = transport.waitForResponse("palizade-lock-probe-3", timeoutMs);
  await transport.send({ jsonrpc: "2.0", id: "palizade-lock-probe-3", method: "tools/list", params: {} });
  const toolsResponse = await toolsPromise;
  await transport.close();
  if ("error" in toolsResponse) {
    throw new Error(`tools/list over HTTP failed: ${toolsResponse.error.message}`);
  }
  const tools = (toolsResponse as { result?: { tools?: unknown } }).result?.tools;
  return Array.isArray(tools) ? (tools as McpTool[]) : [];
}
