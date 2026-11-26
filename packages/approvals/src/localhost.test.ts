import { ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { request } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LocalhostApprovalProvider } from "./localhost.js";
import { createApprovalRequest } from "./terminal.js";

vi.mock("node:child_process", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:child_process")>();
  return { ...original, spawn: vi.fn(original.spawn) };
});

vi.mock("node:os", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:os")>();
  return { ...original, homedir: vi.fn(original.homedir) };
});

describe("LocalhostApprovalProvider", () => {
  let root: string;
  let userHome: string;
  let output: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "palizade-approval-"));
    userHome = join(root, "user");
    vi.mocked(homedir).mockReturnValue(userHome);
    output = "";
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      output += String(chunk);
      return true;
    });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(root, { recursive: true, force: true });
  });

  async function pendingApproval() {
    const stateDir = join(root, "workspace", ".palizade");
    const provider = new LocalhostApprovalProvider({
      defaultDecision: "deny", port: 0, stateDir, openBrowser: false
    });
    const decision = provider.requestApproval(createApprovalRequest({
      sessionId: "test", reason: "Review a sample request", taintIds: [], summary: "Sample action", timeoutMs: 1_000,
      details: { allowAlways: true }
    }));
    await vi.waitFor(() => expect(output.includes("Approval URL file: ")).toBe(true));
    return {
      stateDir,
      inbox: new URL(extractLineValue(output, "[palizade] Approval inbox")),
      file: extractLineValue(output, "[palizade] Approval URL file"),
      decision
    };
  }

  it("refuses an inbox request without its secret and exposes no decision token", async () => {
    const { inbox, decision } = await pendingApproval();
    try {
      const response = await fetch(new URL("/", inbox));
      expect.soft(response.status).toBe(403);
      expect.soft((await response.text()).includes("token=")).toBe(false);
    } finally {
      await decision;
    }
  });

  it.each(["Host", "Origin"])("refuses a decision with a foreign %s", async (header) => {
    const { inbox, decision } = await pendingApproval();
    try {
      const { cookie, page } = await redeem(inbox);
      const action = page.match(/action="([^"]*remember=always[^"]*)"/u)?.[1];
      expect(Boolean(action)).toBe(true);
      const decisionUrl = new URL(decodeHtmlAttribute(action ?? ""), inbox);
      const status = await new Promise<number | undefined>((resolve, reject) => {
        request(decisionUrl, { method: "POST", headers: { Cookie: cookie, [header]: header === "Host" ? `foreign.test:${inbox.port}` : "http://foreign.test" } }, (response) => {
          response.resume();
          resolve(response.statusCode);
        }).once("error", reject).end();
      });
      expect(status).toBe(403);
    } finally {
      await decision;
    }
    expect((await decision).approved).toBe(false);
  });

  it("keeps the approval URL file out of workspace state", async () => {
    const { stateDir, file, decision } = await pendingApproval();
    try {
      await waitForFile(file, /Pending approvals: 1/u);
      await expect(access(join(stateDir, "pending-approval.url"))).rejects.toMatchObject({ code: "ENOENT" });
      const key = createHash("sha256").update(stateDir).digest("hex");
      expect(file).toBe(join(userHome, ".palizade", "run", key, "pending-approval.url"));
    } finally {
      await decision;
    }
  });

  it("writes a durable approval URL file and resolves browser approval", async () => {
    const configPath = join(root, "workspace", "palizade.yaml");
    const provider = new LocalhostApprovalProvider({
      defaultDecision: "deny",
      host: "127.0.0.1",
      port: 0,
      configPath,
      openBrowser: false
    });

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

    const key = createHash("sha256").update(configPath).digest("hex");
    const urlFile = join(userHome, ".palizade", "run", key, "pending-approval.url");
    const contents = await waitForFile(urlFile, /Pending approvals: 1/u);
    expect(contents).toContain("Palizade approval inbox");
    expect(contents).toContain("Tool: post_data");

    const inbox = new URL(extractLineValue(output, "[palizade] Approval inbox"));
    expect(inbox.searchParams.has("code")).toBe(true);
    expect(extractLineValue(contents, "Inbox")).toBe(inbox.origin + "/");
    expect(contents.includes("token=")).toBe(false);
    const { cookie, page: approvalPage } = await redeem(inbox);
    expect((await fetch(inbox, { redirect: "manual", headers: { Cookie: cookie } })).status).toBe(403);
    expect((await fetch(new URL("/", inbox))).status).toBe(403);
    expect(approvalPage).toContain("Palizade approval required");
    expect(approvalPage).toContain("post_data");
    expect(approvalPage).not.toMatch(/<script|requestAnimationFrame|fps/iu);

    const approvePath = approvalPage.match(/action="([^"]*approved=true[^"]*)"/u)?.[1];
    expect(approvePath).toBeDefined();
    const approveUrl = new URL(decodeHtmlAttribute(approvePath ?? ""), inbox);
    expect((await fetch(approveUrl, { headers: { Cookie: cookie } })).status).toBe(405);
    expect((await fetch(approveUrl, { method: "POST", headers: { Origin: inbox.origin } })).status).toBe(403);
    const response = await new Promise<{ status: number | undefined; body: string }>((resolve, reject) => {
      const host = `localhost:${inbox.port}`;
      request(approveUrl, { method: "POST", headers: { Host: host, Origin: `http://${host}`, Cookie: cookie } }, (response) => {
        let body = "";
        response.setEncoding("utf8").on("data", (chunk) => { body += chunk; });
        response.on("end", () => resolve({ status: response.statusCode, body }));
      }).once("error", reject).end();
    });
    expect(response.status).toBe(200);
    expect(response.body).toContain("Approved &mdash; the action will proceed.");

    const decision = await decisionPromise;
    expect(decision.approved).toBe(true);
    expect(decision.approver).toBe("localhost");
    expect(decision.approvalUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/u);
    expect(decision.approvalFile).toBe(urlFile);

    const settled = await readFile(urlFile, "utf8");
    expect(settled).toContain("Pending approvals: 0");
    expect(extractLineValue(settled, "Inbox")).toBe(inbox.origin + "/");
    expect(settled.includes(inbox.searchParams.get("code")!)).toBe(false);
    expect(settled.includes(cookie.split("=")[1]!)).toBe(false);

    const replay = await fetch(approveUrl, { method: "POST", headers: { Cookie: cookie } });
    expect(replay.status).toBe(403);
    expect(await replay.text()).toContain("Invalid or expired approval token");
  });

  it("returns the approval inbox and file path if the browser launcher is unavailable and the request times out", async () => {
    vi.mocked(spawn).mockImplementationOnce(() => {
      const child = new ChildProcess();
      queueMicrotask(() => child.emit("error", new Error("browser launcher unavailable")));
      return child;
    });
    const provider = new LocalhostApprovalProvider({
      defaultDecision: "deny",
      host: "127.0.0.1",
      port: 0,
      stateDir: root
    });

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
    const key = createHash("sha256").update(root).digest("hex");
    const file = join(userHome, ".palizade", "run", key, "pending-approval.url");
    expect(decision.approvalFile).toBe(file);
    expect(output).toContain("Failed to open the browser");
    const contents = await readFile(file, "utf8");
    expect(contents).toContain("Pending approvals: 0");
  });

  it("keeps two listeners independently usable in one emulated browser cookie jar", async () => {
    const rootA = join(root, "ws-a", ".palizade");
    const rootB = join(root, "ws-b", ".palizade");
    const providerA = new LocalhostApprovalProvider({ defaultDecision: "deny", port: 0, stateDir: rootA, openBrowser: false });
    const providerB = new LocalhostApprovalProvider({ defaultDecision: "deny", port: 0, stateDir: rootB, openBrowser: false });

    const decisionAPromise = providerA.requestApproval(createApprovalRequest({
      sessionId: "s-a", reason: "Approve A", taintIds: [], summary: "Action A", timeoutMs: 2_000
    }));
    const decisionBPromise = providerB.requestApproval(createApprovalRequest({
      sessionId: "s-b", reason: "Approve B", taintIds: [], summary: "Action B", timeoutMs: 2_000
    }));

    let inboxes: string[] = [];
    await vi.waitFor(() => {
      inboxes = output
        .split(/\r?\n/u)
        .filter((line) => line.startsWith("[palizade] Approval inbox: "))
        .map((line) => line.slice("[palizade] Approval inbox: ".length));
      expect(inboxes).toHaveLength(2);
    });
    const inboxA = new URL(inboxes[0]!);
    const inboxB = new URL(inboxes[1]!);

    try {
      // Simulate one browser cookie jar keyed by cookie name (same host 127.0.0.1, Path=/).
      const jar = new Map<string, string>();
      const cookieHeader = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
      const storeSetCookie = (setCookie: string) => {
        const eq = setCookie.indexOf("=");
        const semi = setCookie.indexOf(";");
        expect(eq).toBeGreaterThan(0);
        jar.set(setCookie.slice(0, eq), setCookie.slice(eq + 1, semi > eq ? semi : undefined));
      };

      const redeemA = await fetch(inboxA, { redirect: "manual" });
      expect(redeemA.status).toBe(303);
      storeSetCookie(redeemA.headers.get("set-cookie") ?? "");
      expect((await fetch(new URL("/", inboxA), { headers: { Cookie: cookieHeader() } })).status).toBe(200);

      const redeemB = await fetch(inboxB, { redirect: "manual" });
      expect(redeemB.status).toBe(303);
      storeSetCookie(redeemB.headers.get("set-cookie") ?? "");
      expect(jar.size).toBe(2);

      // Opening B must not lock the operator out of A, and both must accept decisions.
      const pageAResp = await fetch(new URL("/", inboxA), { headers: { Cookie: cookieHeader() } });
      expect(pageAResp.status).toBe(200);
      const pageA = await pageAResp.text();
      const pageBResp = await fetch(new URL("/", inboxB), { headers: { Cookie: cookieHeader() } });
      expect(pageBResp.status).toBe(200);
      const pageB = await pageBResp.text();

      const actionA = pageA.match(/action="([^"]*approved=true[^"]*)"/u)?.[1];
      const actionB = pageB.match(/action="([^"]*approved=true[^"]*)"/u)?.[1];
      expect(Boolean(actionA) && Boolean(actionB)).toBe(true);

      const postA = await fetch(new URL(decodeHtmlAttribute(actionA!), inboxA), { method: "POST", headers: { Cookie: cookieHeader() } });
      const postB = await fetch(new URL(decodeHtmlAttribute(actionB!), inboxB), { method: "POST", headers: { Cookie: cookieHeader() } });
      expect(postA.status).toBe(200);
      expect(postB.status).toBe(200);
      expect((await decisionAPromise).approved).toBe(true);
      expect((await decisionBPromise).approved).toBe(true);
    } finally {
      await Promise.allSettled([decisionAPromise, decisionBPromise]);
    }
  });
});

async function redeem(inbox: URL): Promise<{ cookie: string; page: string }> {
  const redemption = await fetch(inbox, { redirect: "manual" });
  expect(redemption.status).toBe(303);
  expect(redemption.headers.get("location")).toBe("/");
  const setCookie = redemption.headers.get("set-cookie") ?? "";
  expect(/^palizade_inbox_\d+_[0-9a-f]+=[\w-]+; HttpOnly; SameSite=Strict; Path=\/$/u.test(setCookie)).toBe(true);
  const cookie = setCookie.split(";")[0]!;
  const page = await fetch(new URL("/", inbox), { headers: { Cookie: cookie } });
  expect(page.status).toBe(200);
  expect(page.headers.get("referrer-policy")).toBe("origin");
  return { cookie, page: await page.text() };
}

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
