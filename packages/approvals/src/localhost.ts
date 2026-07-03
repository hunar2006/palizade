import { createServer, type Server } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { ApprovalDecision, ApprovalDefault, ApprovalProvider, ApprovalRequest } from "./types.js";

export interface LocalhostApprovalOptions {
  defaultDecision: ApprovalDefault;
  host?: string;
}

export class LocalhostApprovalProvider implements ApprovalProvider {
  constructor(private readonly options: LocalhostApprovalOptions = { defaultDecision: "deny", host: "127.0.0.1" }) {}

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    return await new Promise((resolve) => {
      let settled = false;
      let tokenUsed = false;
      const token = randomBytes(32).toString("base64url");
      const server = createServer((req, res) => {
        const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
        const headers = secureHeaders();
        if (url.pathname === "/decision") {
          if (req.method !== "POST") {
            res.writeHead(405, headers);
            res.end("POST required");
            return;
          }
          if (tokenUsed || !safeEqual(url.searchParams.get("token") ?? "", token)) {
            res.writeHead(403, headers);
            res.end("Invalid or replayed approval token");
            return;
          }
          tokenUsed = true;
          const approved = url.searchParams.get("approved") === "true";
          settle(server, resolve, {
            approved,
            reason: approved ? "approved in localhost browser" : "denied in localhost browser",
            approver: "localhost"
          });
          res.writeHead(200, headers);
          res.end(`<h1>Palizade ${approved ? "approved" : "denied"}</h1><p>You can close this tab.</p>`);
          settled = true;
          return;
        }

        if (url.searchParams.get("token") !== token) {
          res.writeHead(403, headers);
          res.end("Invalid approval token");
          return;
        }
        res.writeHead(200, headers);
        res.end(renderApprovalPage(request, token));
      });

      server.listen(0, this.options.host ?? "127.0.0.1", () => {
        const address = server.address() as AddressInfo;
        const url = `http://${address.address}:${address.port}/?token=${encodeURIComponent(token)}`;
        process.stderr.write(`[palizade] Approval required: ${url}\n`);
      });

      const timeout = setTimeout(() => {
        if (settled) {
          return;
        }
        settle(server, resolve, {
          approved: this.options.defaultDecision === "allow",
          reason: `localhost approval timed out; defaulted to ${this.options.defaultDecision}`,
          approver: "localhost"
        });
      }, request.timeoutMs);
      timeout.unref();
    });
  }
}

function settle(server: Server, resolve: (decision: ApprovalDecision) => void, decision: ApprovalDecision): void {
  server.close(() => resolve(decision));
}

function renderApprovalPage(request: ApprovalRequest, token: string): string {
  const rows: Array<[string, string]> = [
    ["Session", request.sessionId],
    ["Server", request.server ?? "-"],
    ["Tool", request.tool ?? "-"],
    ["Method", request.method ?? "-"],
    ["Reason", request.reason],
    ["Taint", request.taintIds.slice(0, 5).join(", ") || "-"],
    ["Summary", redactSensitive(request.summary)]
  ];
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
  <h1>Palizade approval required</h1>
  <table>${rows.map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td><pre>${escapeHtml(value)}</pre></td></tr>`).join("")}</table>
  <form method="post" action="/decision?approved=true&token=${encodeURIComponent(token)}" style="display:inline">
    <button class="approve" type="submit">Approve</button>
  </form>
  <form method="post" action="/decision?approved=false&token=${encodeURIComponent(token)}" style="display:inline">
    <button class="deny" type="submit">Deny</button>
  </form>
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
