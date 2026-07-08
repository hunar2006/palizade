import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LocalhostApprovalProvider } from "./localhost.js";
import { createApprovalRequest } from "./terminal.js";

describe("LocalhostApprovalProvider", () => {
  it("writes a durable approval URL file and resolves browser approval", async () => {
    const root = await mkdtemp(join(tmpdir(), "palizade-approval-"));
    await mkdir(root, { recursive: true });
    const provider = new LocalhostApprovalProvider({
      defaultDecision: "deny",
      host: "127.0.0.1",
      port: 0,
      stateDir: root,
      openBrowser: false
    });

    try {
      const decisionPromise = provider.requestApproval(createApprovalRequest({
        sessionId: "session-test",
        server: "fetch",
        tool: "post_data",
        method: "tools/call",
        reason: "Tainted content is flowing into a sink tool.",
        taintIds: ["taint_1"],
        summary: "post_data wants to run with one taint match.",
        timeoutMs: 1_000
      }));

      const urlFile = join(root, "pending-approval.url");
      const contents = await waitForFile(urlFile, /Request: http:\/\/127\.0\.0\.1:\d+\/approval\//u);
      expect(contents).toContain("Palizade approval inbox");
      expect(contents).toContain("Tool: post_data");

      const requestUrl = extractLineValue(contents, "Request");
      const approvalPage = await (await fetch(requestUrl)).text();
      expect(approvalPage).toContain("Palizade approval required");
      expect(approvalPage).toContain("post_data");
      expect(approvalPage).not.toMatch(/<script|requestAnimationFrame|fps/iu);

      const approvePath = approvalPage.match(/action="([^"]*approved=true[^"]*)"/u)?.[1];
      expect(approvePath).toBeDefined();
      const approveUrl = new URL(decodeHtmlAttribute(approvePath ?? ""), requestUrl);
      const response = await fetch(approveUrl, { method: "POST" });
      expect(response.status).toBe(200);
      expect(await response.text()).toContain("Approved &mdash; the action will proceed.");

      const decision = await decisionPromise;
      expect(decision.approved).toBe(true);
      expect(decision.approver).toBe("localhost");
      expect(decision.approvalUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/u);
      expect(decision.approvalFile).toBe(urlFile);

      const replay = await fetch(approveUrl, { method: "POST" });
      expect(replay.status).toBe(403);
      expect(await replay.text()).toContain("Invalid or expired approval token");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("returns the approval inbox and file path when a request times out", async () => {
    const root = await mkdtemp(join(tmpdir(), "palizade-approval-"));
    const provider = new LocalhostApprovalProvider({
      defaultDecision: "deny",
      host: "127.0.0.1",
      port: 0,
      stateDir: root,
      openBrowser: false
    });

    try {
      const decision = await provider.requestApproval(createApprovalRequest({
        sessionId: "session-test",
        server: "fetch",
        tool: "post_data",
        method: "tools/call",
        reason: "Tainted content is flowing into a sink tool.",
        taintIds: ["taint_1"],
        summary: "post_data wants to run with one taint match.",
        timeoutMs: 10
      }));

      expect(decision.approved).toBe(false);
      expect(decision.reason).toContain("localhost approval timed out");
      expect(decision.approvalUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/u);
      expect(decision.approvalFile).toBe(join(root, "pending-approval.url"));
      const contents = await readFile(join(root, "pending-approval.url"), "utf8");
      expect(contents).toContain("Pending approvals: 0");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

async function waitForFile(path: string, pattern: RegExp): Promise<string> {
  const started = Date.now();
  while (Date.now() - started < 1_000) {
    try {
      const contents = await readFile(path, "utf8");
      if (pattern.test(contents)) {
        return contents;
      }
    } catch {
      // Keep polling until the provider writes the file.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${path}`);
}

function extractLineValue(contents: string, label: string): string {
  const line = contents.split(/\r?\n/u).find((entry) => entry.startsWith(`${label}: `));
  if (!line) {
    throw new Error(`Missing ${label} line`);
  }
  return line.slice(label.length + 2);
}

function decodeHtmlAttribute(value: string): string {
  return value.replace(/&amp;/gu, "&").replace(/&quot;/gu, "\"");
}
