import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ApprovalDecision, ApprovalDefault, ApprovalProvider, ApprovalRequest } from "./types.js";

const DEFAULT_APPROVAL_PORT = 32145;
const loopbackHosts = ["127.0.0.1", "localhost", "[::1]"];

export interface LocalhostApprovalOptions {
  defaultDecision: ApprovalDefault;
  host?: string;
  port?: number;
  configPath?: string;
  stateDir?: string;
  openBrowser?: boolean;
}

interface PendingApproval {
  request: ApprovalRequest;
  token: string;
  timeout: NodeJS.Timeout;
  resolve: (decision: ApprovalDecision) => void;
}

export class LocalhostApprovalProvider implements ApprovalProvider {
  private readonly pending = new Map<string, PendingApproval>();
  private readonly listenerId = randomBytes(8).toString("hex");
  private cookieName = `palizade_inbox_0_${this.listenerId}`;
  private serverPromise: Promise<void> | undefined;
  private server: Server | undefined;
  private inboxUrl: string | undefined;
  private redeemCode: string | undefined;
  private sessionSecret: string | undefined;
  private fileWrite = Promise.resolve();
  private readonly pendingUrlFile: string | undefined;

  constructor(private readonly options: LocalhostApprovalOptions = { defaultDecision: "deny", host: "127.0.0.1", port: DEFAULT_APPROVAL_PORT }) {
    const location = options.configPath ?? options.stateDir;
    if (location) {
      const key = createHash("sha256").update(resolve(location)).digest("hex");
      this.pendingUrlFile = join(homedir(), ".palizade", "run", key, "pending-approval.url");
    }
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    try {
      await this.ensureServer();
    } catch (error) {
      return {
        approved: this.options.defaultDecision === "allow",
        reason: `localhost approval server failed (${error instanceof Error ? error.message : String(error)}); defaulted to ${this.options.defaultDecision}`,
        approver: "localhost"
      };
    }

    return await new Promise((resolve) => {
      const token = randomBytes(32).toString("base64url");
      const inboxUrl = this.inboxUrl!;
      const newBatch = this.pending.size === 0;
      const timeout = setTimeout(() => {
        void this.settlePending(request.id, {
          approved: this.options.defaultDecision === "allow",
          reason: `localhost approval timed out; defaulted to ${this.options.defaultDecision}`,
          approver: "localhost",
          approvalUrl: inboxUrl,
          approvalFile: this.pendingUrlFile
        });
      }, request.timeoutMs);
      timeout.unref();

      this.pending.set(request.id, {
        request,
        token,
        timeout,
        resolve
      });

      void this.writePendingUrlFile();
      if (newBatch) {
        this.sessionSecret = undefined;
        this.redeemCode = randomBytes(32).toString("base64url");
        const inboxLink = `${inboxUrl}?code=${this.redeemCode}`;
        process.stderr.write(`[palizade] Approval inbox: ${inboxLink}\n`);
        if (this.options.openBrowser !== false) openBrowser(inboxLink);
      }
      if (this.pendingUrlFile) {
        process.stderr.write(`[palizade] Approval URL file: ${this.pendingUrlFile}\n`);
      }
    });
  }

  private async ensureServer(): Promise<void> {
    if (!this.serverPromise) {
      this.serverPromise = this.startServer();
    }
    return this.serverPromise;
  }

  private async startServer(): Promise<void> {
    const requestedHost = (this.options.host ?? "127.0.0.1").toLowerCase();
    const host = requestedHost === "[::1]" ? "::1" : requestedHost;
    if (!loopbackHosts.includes(hostForUrl(host))) throw new Error("The approval server must bind to loopback.");
    const preferredPort = this.options.port ?? DEFAULT_APPROVAL_PORT;
    try {
      await this.listen(host, preferredPort);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EADDRINUSE" || preferredPort === 0) {
        throw error;
      }
      process.stderr.write(`[palizade] Approval port ${preferredPort} is in use; falling back to an ephemeral port.\n`);
      await this.listen(host, 0);
    }
  }

  private async listen(host: string, port: number): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const server = createServer((req, res) => this.handleRequest(req, res));
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        server.unref();
        const address = server.address() as AddressInfo;
        this.server = server;
        this.cookieName = `palizade_inbox_${address.port}_${this.listenerId}`;
        this.inboxUrl = `http://${hostForUrl(address.address)}:${address.port}/`;
        process.stderr.write(`[palizade] Approval inbox listening at ${this.inboxUrl}\n`);
        resolve();
      });
    });
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const headers = secureHeaders();
    const inbox = new URL(this.inboxUrl!);
    const host = req.headers.host?.toLowerCase();
    if (!loopbackHosts.some((name) => host === `${name}:${inbox.port || "80"}` || (!inbox.port && host === name))) {
      res.writeHead(403, headers);
      res.end("Invalid approval host");
      return;
    }
    const origin = new URL(`http://${host}`).origin;
    const url = URL.parse(req.url ?? "/", origin);
    if (!url || url.origin !== origin) {
      res.writeHead(403, headers);
      res.end("Invalid approval URL");
      return;
    }

    if (req.headers.origin !== undefined && origin !== req.headers.origin) {
      res.writeHead(403, headers);
      res.end("Invalid approval origin");
      return;
    }
    const code = url.searchParams.get("code");
    if (url.pathname === "/" && req.method === "GET" && code !== null) {
      if (!this.redeemCode || !safeEqual(code, this.redeemCode)) {
        res.writeHead(403, headers);
        res.end("Open the approval inbox link from the Palizade terminal.");
        return;
      }
      this.redeemCode = undefined;
      this.sessionSecret = randomBytes(32).toString("base64url");
      res.writeHead(303, { ...headers, location: "/", "set-cookie": `${this.cookieName}=${this.sessionSecret}; HttpOnly; SameSite=Strict; Path=/` });
      res.end();
      return;
    }

    const cookie = req.headers.cookie
      ?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${this.cookieName}=`))
      ?.slice(this.cookieName.length + 1);
    if ((url.pathname === "/" || url.pathname === "/decision") &&
        (!this.sessionSecret || !safeEqual(cookie ?? "", this.sessionSecret))) {
      res.writeHead(403, headers);
      res.end("Open the approval inbox link from the Palizade terminal.");
      return;
    }

    if (url.pathname === "/" && req.method === "GET") {
      res.writeHead(200, headers);
      res.end(renderInboxPage([...this.pending.values()]));
      return;
    }

    if (url.pathname === "/decision") {
      if (req.method !== "POST") {
        res.writeHead(405, headers);
        res.end("POST required");
        return;
      }
      const pending = this.findPending(url.searchParams.get("id"), url.searchParams.get("token") ?? "");
      if (!pending) {
        res.writeHead(403, headers);
        res.end("Invalid or expired approval token");
        return;
      }
      const approved = url.searchParams.get("approved") === "true";
      void this.settlePending(pending.request.id, {
        approved,
        remember: approved && pending.request.details?.allowAlways === true && url.searchParams.get("remember") === "always" ? "always" : approved && pending.request.details?.allowSession === true && url.searchParams.get("remember") === "session" ? "session" : "once",
        reason: approved ? "approved in localhost browser" : "denied in localhost browser",
        approver: "localhost",
        approvalUrl: this.inboxUrl,
        approvalFile: this.pendingUrlFile
      });
      res.writeHead(200, headers);
      res.end(renderDecisionPage(approved));
      return;
    }

    res.writeHead(404, headers);
    res.end("Not found");
  }

  private findPending(id: string | null, token: string): PendingApproval | undefined {
    if (!token) {
      return undefined;
    }
    if (id) {
      const byId = this.pending.get(id);
      if (byId && safeEqual(token, byId.token)) {
        return byId;
      }
    }
    return [...this.pending.values()].find((pending) => safeEqual(token, pending.token));
  }

  private async settlePending(id: string, decision: ApprovalDecision): Promise<void> {
    const pending = this.pending.get(id);
    if (!pending) {
      return;
    }
    clearTimeout(pending.timeout);
    this.pending.delete(id);
    if (this.pending.size === 0) this.redeemCode = undefined;
    await this.writePendingUrlFile();
    pending.resolve(decision);
  }

  private writePendingUrlFile(): Promise<void> {
    const file = this.pendingUrlFile;
    if (!file || !this.inboxUrl) return Promise.resolve();
    this.fileWrite = this.fileWrite.then(async () => {
      await mkdir(dirname(file), { recursive: true, mode: 0o700 });
      const lines = [
        "Palizade approval inbox",
        `Inbox: ${this.inboxUrl}`,
        `Pending approvals: ${this.pending.size}`,
        "",
        ...[...this.pending.values()].flatMap((pending) => [
          `Server: ${pending.request.server ?? "-"}`,
          `Tool: ${pending.request.tool ?? "-"}`,
          `Reason: ${pending.request.reason}`,
          ""
        ])
      ];
      await writeFile(file, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
    }).catch((error) => {
      process.stderr.write(`[palizade] Failed to write approval URL file: ${error instanceof Error ? error.message : String(error)}\n`);
    });
    return this.fileWrite;
  }
}

function renderApprovalPanel(request: ApprovalRequest, token: string): string {
  const alwaysAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "true", remember: "always", token }).toString()}`);
  const sessionAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "true", remember: "session", token }).toString()}`);
  const approveAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "true", token }).toString()}`);
  const denyAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "false", token }).toString()}`);
  const rows: Array<[string, string]> = [
    ["Session", request.sessionId],
    ["Server", request.server ?? "-"],
    ["Tool", request.tool ?? "-"],
    ["Method", request.method ?? "-"],
    ["Reason", request.reason],
    ["Taint matches", request.taintIds.length > 0 ? String(request.taintIds.length) : "-"],
    ["Summary", redactSensitive(request.summary)],
    ...(typeof request.details?.diff === "string" ? [["Diff", request.details.diff] as [string, string]] : [])
  ];
  return `<h1>Palizade approval required</h1>
  <table>${rows.map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td><pre>${escapeHtml(value)}</pre></td></tr>`).join("")}</table>
  <form method="post" action="${approveAction}" style="display:inline">
    <button class="approve" type="submit">Allow once</button>
  </form>
  ${request.details?.allowAlways === true ? `<form method="post" action="${alwaysAction}" style="display:inline"><button class="approve" type="submit">Allow always</button></form>` : ""}
  ${request.details?.allowSession === true ? `<form method="post" action="${sessionAction}" style="display:inline"><button class="approve" type="submit">Trust destination for this session</button></form>` : ""}
  <form method="post" action="${denyAction}" style="display:inline">
    <button class="deny" type="submit">Deny</button>
  </form>`;
}

function renderDecisionPage(approved: boolean): string {
  const message = approved ? "Approved &mdash; the action will proceed." : "Denied.";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Palizade ${approved ? "Approved" : "Denied"}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 20px; line-height: 1.45; }
  </style>
</head>
<body>
  <h1>${message}</h1>
  <p>You can close this tab.</p>
</body>
</html>`;
}

function renderInboxPage(pending: PendingApproval[]): string {
  const body = pending.length === 0
    ? "<p>No approvals are pending. Keep this page open while using Palizade interactive mode.</p>"
    : pending.map((item) => `<section>${renderApprovalPanel(item.request, item.token)}</section>`).join("<hr>");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Palizade Approval Inbox</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 820px; margin: 40px auto; padding: 0 20px; line-height: 1.45; }
    table { border-collapse: collapse; width: 100%; margin: 24px 0; }
    td { border-top: 1px solid #ddd; padding: 10px; vertical-align: top; }
    td:first-child { font-weight: 700; width: 140px; }
    button { display: inline-block; margin-right: 12px; padding: 10px 16px; border: 0; border-radius: 6px; color: white; cursor: pointer; }
    .approve { background: #176f3d; }
    .deny { background: #8a1f1f; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; }
    hr { border: 0; border-top: 1px solid #ddd; margin: 32px 0; }
  </style>
</head>
<body>
  <h1>Palizade approval inbox</h1>
  ${body}
</body>
</html>`;
}

function secureHeaders(): Record<string, string> {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    // Keep the form POST's Origin while omitting the redemption code from its referrer.
    "referrer-policy": "origin"
  };
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function hostForUrl(address: string): string {
  return address.includes(":") ? `[${address}]` : address;
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const command = platform === "win32" ? "cmd" : platform === "darwin" ? "open" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  const reportError = () => {
    process.stderr.write("[palizade] Failed to open the browser. Open the approval inbox link printed above.\n");
  };
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });
    child.once("error", reportError);
    child.unref();
  } catch {
    reportError();
  }
}

function redactSensitive(value: string): string {
  return value
    .replace(/\bhttps?:\/\/[^\s<>"')]+/giu, "[url-redacted]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu, "[email-redacted]");
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}
