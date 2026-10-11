import { timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect, type AddressInfo, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import { domainToASCII } from "node:url";

export interface EgressProxyEvent {
  host: string;
  port: number;
  allowed: boolean;
  method: string;
}

export interface EgressProxyOptions {
  allowHosts: string[];
  /** Address to listen on. Docker containers reach the host through host.docker.internal, so docker launches bind all interfaces. */
  host?: string;
  maxConnections?: number;
  idleTimeoutMs?: number;
  /** When set, clients must send Proxy-Authorization: Basic base64("palizade:<token>"). */
  token?: string;
  onEvent?: (event: EgressProxyEvent) => void;
}

/**
 * Minimal forward proxy for sandboxed servers: CONNECT tunnels and absolute-URI HTTP requests are allowed only
 * to hosts in the allowlist. It never inspects or logs request bodies.
 */
export class EgressProxy {
  private server: Server | undefined;
  private readonly sockets = new Set<Socket | Duplex>();

  constructor(private readonly options: EgressProxyOptions) {}

  async start(): Promise<{ host: string; port: number }> {
    const server = createServer((req, res) => this.handleHttp(req, res));
    server.maxConnections = this.options.maxConnections ?? 64;
    server.on("connect", (req, socket, head) => this.handleConnect(req, socket, head));
    server.on("connection", (socket) => {
      socket.setTimeout(this.options.idleTimeoutMs ?? 120_000, () => socket.destroy());
      this.track(socket);
    });
    await new Promise<void>((resolveListen, reject) => {
      server.once("error", reject);
      server.listen(0, this.options.host ?? "127.0.0.1", () => resolveListen());
    });
    this.server = server;
    const address = server.address() as AddressInfo;
    return { host: this.options.host ?? "127.0.0.1", port: address.port };
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolveClose) => this.server ? this.server.close(() => resolveClose()) : resolveClose());
  }

  isAllowed(host: string): boolean {
    return hostAllowed(this.options.allowHosts, host);
  }

  private handleConnect(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    this.track(socket);
    if (!this.authorized(req)) {
      socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"palizade\"\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    const target = parseAuthority(req.url ?? "");
    if (!target || !this.isAllowed(target.host)) {
      this.emit(target?.host ?? "invalid", target?.port ?? 0, false, "CONNECT");
      socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    this.emit(target.host, target.port, true, "CONNECT");
    const upstream = connect(target.port, target.host, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    this.track(upstream);
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    if (!this.authorized(req)) {
      res.writeHead(407, { "Proxy-Authenticate": "Basic realm=\"palizade\"" }).end();
      return;
    }
    let url: URL;
    try {
      url = new URL(req.url ?? "");
    } catch {
      res.writeHead(400).end();
      return;
    }
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    if (url.protocol !== "http:" || !this.isAllowed(url.hostname)) {
      this.emit(url.hostname, port, false, req.method ?? "GET");
      res.writeHead(403).end();
      return;
    }
    this.emit(url.hostname, port, true, req.method ?? "GET");
    const headers = { ...req.headers };
    delete headers["proxy-authorization"];
    delete headers["proxy-connection"];
    const upstream = httpRequest({ host: url.hostname, port, path: `${url.pathname}${url.search}`, method: req.method, headers }, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
      upstreamRes.pipe(res);
    });
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  }

  private authorized(req: IncomingMessage): boolean {
    if (!this.options.token) return true;
    const expected = Buffer.from(`Basic ${Buffer.from(`palizade:${this.options.token}`).toString("base64")}`);
    const actual = Buffer.from(String(req.headers["proxy-authorization"] ?? ""));
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  private emit(host: string, port: number, allowed: boolean, method: string): void {
    try {
      this.options.onEvent?.({ host, port, allowed, method });
    } catch {
      // Event reporting must never keep a denied connection open or crash the proxy.
    }
  }

  private track(socket: Socket | Duplex): void {
    this.sockets.add(socket);
    socket.once("close", () => this.sockets.delete(socket));
  }
}

export function hostAllowed(allowHosts: string[], host: string): boolean {
  const normalized = normalizeHost(host);
  if (!normalized) return false;
  return allowHosts.some((entry) => {
    const pattern = normalizeHost(entry);
    if (!pattern) return false;
    if (pattern === "*") return true;
    if (pattern.startsWith("*.")) return normalized.endsWith(pattern.slice(1));
    return pattern === normalized;
  });
}

function normalizeHost(value: string): string {
  const trimmed = value.trim().toLowerCase().replace(/^\[|\]$/gu, "").replace(/\.$/u, "");
  if (trimmed.startsWith("*.")) return `*.${domainToASCII(trimmed.slice(2)) || trimmed.slice(2)}`;
  return domainToASCII(trimmed) || trimmed;
}

function parseAuthority(authority: string): { host: string; port: number } | undefined {
  const match = /^\[?([^\]]+?)\]?:(\d{1,5})$/u.exec(authority);
  if (!match) return undefined;
  const port = Number(match[2]);
  if (port < 1 || port > 65_535) return undefined;
  return { host: match[1]!, port };
}
