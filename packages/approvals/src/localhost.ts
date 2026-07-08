import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import type { ApprovalDecision, ApprovalDefault, ApprovalProvider, ApprovalRequest } from "./types.js";

const DEFAULT_APPROVAL_PORT = 32145;

export interface LocalhostApprovalOptions {
  defaultDecision: ApprovalDefault;
  host?: string;
  port?: number;
  stateDir?: string;
  openBrowser?: boolean;
}

interface PendingApproval {
  request: ApprovalRequest;
  token: string;
  approvalUrl: string;
  timeout: NodeJS.Timeout;
  resolve: (decision: ApprovalDecision) => void;
}

export class LocalhostApprovalProvider implements ApprovalProvider {
  private readonly pending = new Map<string, PendingApproval>();
  private serverPromise: Promise<void> | undefined;
  private server: Server | undefined;
  private inboxUrl: string | undefined;
  private readonly pendingUrlFile: string | undefined;

  constructor(private readonly options: LocalhostApprovalOptions = { defaultDecision: "deny", host: "127.0.0.1", port: DEFAULT_APPROVAL_PORT }) {
    this.pendingUrlFile = options.stateDir ? join(options.stateDir, "pending-approval.url") : undefined;
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
      const inboxUrl = this.inboxUrl ?? `http://${this.options.host ?? "127.0.0.1"}:${this.options.port ?? DEFAULT_APPROVAL_PORT}/`;
      const approvalUrl = `${inboxUrl}approval/${encodeURIComponent(request.id)}?token=${encodeURIComponent(token)}`;
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
        approvalUrl,
        timeout,
        resolve
      });

      void this.writePendingUrlFile();
      process.stderr.write(`[palizade] Approval required: ${approvalUrl}\n`);
      process.stderr.write(`[palizade] Approval inbox: ${inboxUrl}\n`);
      if (this.pendingUrlFile) {
        process.stderr.write(`[palizade] Approval URL file: ${this.pendingUrlFile}\n`);
      }
      if (this.options.openBrowser !== false) {
        openBrowser(approvalUrl);
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
    const host = this.options.host ?? "127.0.0.1";
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
    await this.writePendingUrlFile();
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
        this.inboxUrl = `http://${hostForUrl(address.address)}:${address.port}/`;
        process.stderr.write(`[palizade] Approval inbox listening at ${this.inboxUrl}\n`);
        resolve();
      });
    });
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    const headers = secureHeaders();

    if (url.pathname === "/") {
      res.writeHead(200, headers);
      res.end(renderInboxPage([...this.pending.values()]));
      return;
    }

    const approvalMatch = /^\/approval\/([^/]+)$/u.exec(url.pathname);
    if (approvalMatch) {
      const id = decodeURIComponent(approvalMatch[1] ?? "");
      const pending = this.findPending(id, url.searchParams.get("token") ?? "");
      if (!pending) {
        res.writeHead(403, headers);
        res.end("Invalid or expired approval token");
        return;
      }
      res.writeHead(200, headers);
      res.end(renderApprovalPage(pending.request, pending.token));
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
    await this.writePendingUrlFile();
    pending.resolve(decision);
  }

  private async writePendingUrlFile(): Promise<void> {
    if (!this.pendingUrlFile || !this.inboxUrl) {
      return;
    }
    try {
      await mkdir(dirname(this.pendingUrlFile), { recursive: true });
      const lines = [
        "Palizade approval inbox",
        `Inbox: ${this.inboxUrl}`,
        `Pending approvals: ${this.pending.size}`,
        "",
        ...[...this.pending.values()].flatMap((pending) => [
          `Request: ${pending.approvalUrl}`,
          `Server: ${pending.request.server ?? "-"}`,
          `Tool: ${pending.request.tool ?? "-"}`,
          `Reason: ${pending.request.reason}`,
          `Approve with browser: ${pending.approvalUrl}`,
          ""
        ])
      ];
      await writeFile(this.pendingUrlFile, `${lines.join("\n")}\n`, "utf8");
    } catch (error) {
      process.stderr.write(`[palizade] Failed to write approval URL file: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  }
}

function renderApprovalPage(request: ApprovalRequest, token: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Palizade Approval</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 20px; line-height: 1.45; }
    table { border-collapse: collapse; width: 100%; margin: 24px 0; }
    td { border-top: 1px solid #ddd; padding: 10px; vertical-align: top; }
    td:first-child { font-weight: 700; width: 140px; }
    button { display: inline-block; margin-right: 12px; padding: 10px 16px; border: 0; border-radius: 6px; color: white; cursor: pointer; }
    .approve { background: #176f3d; }
    .deny { background: #8a1f1f; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  ${renderApprovalPanel(request, token)}
</body>
</html>`;
}

function renderApprovalPanel(request: ApprovalRequest, token: string): string {
  const approveAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "true", token }).toString()}`);
  const denyAction = escapeHtml(`/decision?${new URLSearchParams({ id: request.id, approved: "false", token }).toString()}`);
  const rows: Array<[string, string]> = [
    ["Session", request.sessionId],
    ["Server", request.server ?? "-"],
    ["Tool", request.tool ?? "-"],
    ["Method", request.method ?? "-"],
    ["Reason", request.reason],
    ["Taint matches", request.taintIds.length > 0 ? String(request.taintIds.length) : "-"],
    ["Summary", redactSensitive(request.summary)]
  ];
  return `<h1>Palizade approval required</h1>
  <table>${rows.map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td><pre>${escapeHtml(value)}</pre></td></tr>`).join("")}</table>
  <form method="post" action="${approveAction}" style="display:inline">
    <button class="approve" type="submit">Approve</button>
  </form>
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
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function hostForUrl(address: string): string {
  if (address === "::" || address === "0.0.0.0") {
    return "127.0.0.1";
  }
  return address.includes(":") ? `[${address}]` : address;
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const command = platform === "win32" ? "cmd" : platform === "darwin" ? "open" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });
    child.unref();
  } catch (error) {
    process.stderr.write(`[palizade] Failed to open approval URL: ${error instanceof Error ? error.message : String(error)}\n`);
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
