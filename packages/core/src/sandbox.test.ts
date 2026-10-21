import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger, type AuditEvent } from "@palizade/audit";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";
import { EgressProxy } from "./egress-proxy.js";
import { launchUpstream } from "./launch.js";
import { assertSandboxSupported, buildLaunchPlan, describeLaunchForAudit, DOCKER_WORKDIR, sandboxStatus } from "./sandbox.js";

const dirs: string[] = [];
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "palizade-sandbox-"));
  dirs.push(dir);
  return dir;
}

describe("sandbox config validation", () => {
  it("allows only docker on Windows with a clear message", () => {
    const server = { command: "node", args: [], env: {} };
    expect(() => assertSandboxSupported("fs", { ...server, sandbox: "bubblewrap" }, "win32")).toThrow(/bubblewrap only runs on Linux.*On Windows only sandbox: docker is available/u);
    expect(() => assertSandboxSupported("fs", { ...server, sandbox: "seatbelt" }, "win32")).toThrow(/On Windows only sandbox: docker is available/u);
    expect(assertSandboxSupported("fs", { ...server, sandbox: "docker" }, "win32").type).toBe("docker");
    expect(assertSandboxSupported("fs", server, "win32").type).toBe("none");
  });

  it("checks bubblewrap and seatbelt per platform", () => {
    const server = { command: "node", args: [], env: {} };
    expect(assertSandboxSupported("fs", { ...server, sandbox: "bubblewrap" }, "linux").type).toBe("bubblewrap");
    expect(() => assertSandboxSupported("fs", { ...server, sandbox: "seatbelt" }, "linux")).toThrow(/only runs on macOS/u);
    expect(assertSandboxSupported("fs", { ...server, sandbox: "seatbelt" }, "darwin").type).toBe("seatbelt");
    expect(() => assertSandboxSupported("fs", { ...server, sandbox: "bubblewrap" }, "darwin")).toThrow(/only runs on Linux/u);
  });

  it("validates sandbox options in palizade.yaml", () => {
    expect(() => parseConfig("servers:\n  fs: { command: node, sandbox: { type: docker, network: allowlist } }\n")).toThrow(/allowHosts/u);
    expect(() => parseConfig("servers:\n  fs: { command: node, sandbox: { type: docker, passEnv: ['A=B'] } }\n")).toThrow(/environment variable names/u);
    expect(() => parseConfig("servers:\n  remote: { url: 'https://example.test/mcp', sandbox: docker }\n")).toThrow(/only to stdio servers/u);
    const config = parseConfig("servers:\n  fs: { command: node, sandbox: docker }\n  plain: { command: node }\n");
    expect(config.servers.fs?.sandbox).toBe("docker");
    expect(sandboxStatus(config.servers, "win32").map((row) => [row.server, row.status])).toEqual([["fs", "sandboxed"], ["plain", "unsandboxed"]]);
  });
});

describe("docker launch plan", () => {
  it("builds a locked down docker argument list without environment values", async () => {
    const cwd = await tempDir();
    const plan = buildLaunchPlan("fs", {
      command: "node",
      args: ["server.js", "/workspace"],
      cwd,
      env: { GITHUB_TOKEN: "ghp_secretvalue123456" },
      sandbox: { type: "docker", image: "palizade/fs:1", writable: ["out"], network: "none", allowHosts: [], passEnv: ["LANG"], pidsLimit: 128, advisoryNetwork: false }
    }, { platform: "win32", hostEnv: { PATH: "C:\\bin", LANG: "en_US.UTF-8", AWS_SECRET_ACCESS_KEY: "nope" } });

    expect(plan.command).toBe("docker");
    const args = plan.args;
    expect(args.slice(0, 4)).toEqual(["run", "--rm", "-i", "--init"]);
    expect(args).toEqual(expect.arrayContaining(["--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--read-only", "--network", "none", "--pids-limit", "128"]));
    expect(args).toContain(`type=bind,source=${cwd},target=${DOCKER_WORKDIR},readonly`);
    expect(args).toContain(`type=bind,source=${join(cwd, "out")},target=${DOCKER_WORKDIR}/out`);
    expect(args.join(" ")).toContain("-e GITHUB_TOKEN -e LANG");
    expect(args.join(" ")).not.toContain("ghp_secretvalue123456");
    expect(args.join(" ")).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(args.slice(-4)).toEqual(["palizade/fs:1", "node", "server.js", "/workspace"]);
    expect(plan.env.GITHUB_TOKEN).toBe("ghp_secretvalue123456");
  });

  it("routes allowlisted egress through the proxy and masks its credential in audit", () => {
    const server = {
      command: "node",
      args: ["--token=abc123secret"],
      cwd: process.cwd(),
      env: {},
      sandbox: { type: "docker" as const, writable: [], network: "allowlist" as const, allowHosts: ["api.github.com"], passEnv: [], pidsLimit: 512, advisoryNetwork: true }
    };
    const plan = buildLaunchPlan("gh", server, { platform: "linux", hostEnv: {}, proxy: { host: "127.0.0.1", port: 4100, token: "proxytoken" } });
    expect(plan.args).toEqual(expect.arrayContaining(["--network", "bridge", "--add-host", "host.docker.internal:host-gateway"]));
    expect(plan.args).toContain("HTTPS_PROXY=http://palizade:proxytoken@host.docker.internal:4100");
    const audit = JSON.stringify(describeLaunchForAudit(plan, server));
    expect(audit).not.toContain("proxytoken");
    expect(audit).not.toContain("abc123secret");
  });

  it.skipIf(!dockerImagePresent("node:22-slim"))("runs a server inside docker when docker and the image are available", async () => {
    const cwd = await tempDir();
    const { child } = await launchUpstream("echo", { command: "node", args: ["-e", "process.stdout.write('sandboxed')"], cwd, env: {}, sandbox: "docker" }, { resolveCommand: (command) => command });
    const output = await new Promise<string>((resolveOutput) => {
      let text = "";
      child.stdout.on("data", (chunk) => { text += String(chunk); });
      child.on("exit", () => resolveOutput(text));
    });
    expect(output).toBe("sandboxed");
  }, 60_000);
});

describe("sandbox egress proxy", () => {
  it("tunnels to allowlisted hosts and refuses others", async () => {
    const upstream = createServer((_req, res) => res.end("upstream ok"));
    servers.push(upstream);
    await new Promise<void>((resolveListen) => upstream.listen(0, "127.0.0.1", () => resolveListen()));
    const upstreamPort = (upstream.address() as AddressInfo).port;
    const events: Array<{ host: string; allowed: boolean }> = [];
    const proxy = new EgressProxy({ allowHosts: ["127.0.0.1"], token: "t0ken", onEvent: (event) => events.push(event) });
    const bound = await proxy.start();
    const auth = `Basic ${Buffer.from("palizade:t0ken").toString("base64")}`;
    try {
      expect(await proxyGet(bound.port, `http://127.0.0.1:${upstreamPort}/`, auth)).toEqual({ status: 200, body: "upstream ok" });
      expect((await proxyGet(bound.port, "http://evil.example/", auth)).status).toBe(403);
      expect((await proxyGet(bound.port, `http://127.0.0.1:${upstreamPort}/`)).status).toBe(407);
      expect(await proxyConnect(bound.port, `127.0.0.1:${upstreamPort}`, auth)).toBe(200);
      expect(await proxyConnect(bound.port, "evil.example:443", auth)).toBe(403);
      expect(events).toEqual(expect.arrayContaining([
        expect.objectContaining({ host: "127.0.0.1", allowed: true }),
        expect.objectContaining({ host: "evil.example", allowed: false })
      ]));
    } finally {
      await proxy.close();
    }
  });
});

describe("spawn audit", () => {
  it("logs every spawn with masked arguments and no environment values", async () => {
    const events: AuditEvent[] = [];
    const audit = new AuditLogger([{ write: async (event) => { events.push(event); } }]);
    const { child } = await launchUpstream("plain", {
      command: process.execPath,
      args: ["-e", "process.exit(0)", "--api_key=sk-test-should-not-leak"],
      env: { SERVICE_PASSWORD: "hunter2hunter2" },
      sandbox: "none"
    }, { resolveCommand: (command) => command, audit, sessionId: "s1" });
    await new Promise((resolveExit) => child.on("exit", resolveExit));
    const spawn = events.find((event) => event.method === "process/spawn");
    expect(spawn?.metadata?.spawn).toMatchObject({ sandbox: "none", envKeys: ["SERVICE_PASSWORD"] });
    expect(JSON.stringify(spawn)).not.toContain("sk-test-should-not-leak");
    expect(JSON.stringify(spawn)).not.toContain("hunter2hunter2");
  });

  it("refuses to start an unsupported sandbox before spawning anything", async () => {
    const events: AuditEvent[] = [];
    const audit = new AuditLogger([{ write: async (event) => { events.push(event); } }]);
    const unsupported = process.platform === "darwin" ? "bubblewrap" : "seatbelt";
    await expect(launchUpstream("fs", { command: "node", args: [], env: {}, sandbox: unsupported }, { resolveCommand: (command) => command, audit })).rejects.toThrow(/Server 'fs'/u);
    expect(events).toHaveLength(0);
  });
});

function dockerImagePresent(image: string): boolean {
  try {
    return spawnSync("docker", ["image", "inspect", image], { stdio: "ignore", timeout: 5_000 }).status === 0;
  } catch {
    return false;
  }
}

function proxyGet(port: number, url: string, auth?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolveGet, reject) => {
    const req = request({ host: "127.0.0.1", port, path: url, method: "GET", headers: auth ? { "proxy-authorization": auth } : {} }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += String(chunk); });
      res.on("end", () => resolveGet({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function proxyConnect(port: number, authority: string, auth: string): Promise<number> {
  return new Promise((resolveConnect, reject) => {
    const req = request({ host: "127.0.0.1", port, method: "CONNECT", path: authority, headers: { "proxy-authorization": auth } });
    req.on("connect", (res, socket) => {
      socket.destroy();
      resolveConnect(res.statusCode ?? 0);
    });
    req.on("response", (res) => resolveConnect(res.statusCode ?? 0));
    req.on("error", reject);
    req.end();
  });
}

describe("advisory network allowlists", () => {
  it("rejects allowlists the server could route around unless explicitly accepted", async () => {
    const { sandboxObjectSchema } = await import("./sandbox.js");
    const docker = { type: "docker", network: "allowlist", allowHosts: ["api.example.com"] };
    expect(sandboxObjectSchema.safeParse(docker).success).toBe(false);
    expect(sandboxObjectSchema.safeParse({ ...docker, dockerNetwork: "palizade-internal" }).success).toBe(true);
    expect(sandboxObjectSchema.safeParse({ ...docker, advisoryNetwork: true }).success).toBe(true);
    expect(sandboxObjectSchema.safeParse({ ...docker, type: "bubblewrap" }).success).toBe(false);
    expect(sandboxObjectSchema.safeParse({ ...docker, type: "seatbelt" }).success).toBe(true);
    expect(sandboxObjectSchema.safeParse({ type: "docker", network: "none" }).success).toBe(true);
  });
});
