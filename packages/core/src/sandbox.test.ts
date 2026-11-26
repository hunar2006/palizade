import { spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { AuditLogger, type AuditEvent } from "@palizade/audit";
import { afterEach, describe, expect, it, vi } from "vitest";
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

describe("placeholder expansion", () => {
  it("fills ${NAME} from the host env, reports unset names, and masks expanded secrets in audit", () => {
    const server = { command: "node", args: ["${APP_DIR}/server.js", "--token=${API_KEY}"], cwd: process.cwd(), env: { API_KEY: "${API_KEY}", REGION: "${REGION:-us}" } };
    const plan = buildLaunchPlan("api", server, { platform: "linux", hostEnv: { APP_DIR: "/srv/app", API_KEY: "sk_live_expanded_secret" } });
    expect(plan.args).toEqual(["/srv/app/server.js", "--token=sk_live_expanded_secret"]);
    expect(plan.env.API_KEY).toBe("sk_live_expanded_secret");
    expect(plan.env.REGION).toBe("us");
    expect(plan.missingEnv).toBeUndefined();
    expect(JSON.stringify(describeLaunchForAudit(plan, server))).not.toContain("sk_live_expanded_secret");
    expect(buildLaunchPlan("api", server, { platform: "linux", hostEnv: {} }).missingEnv).toEqual(["API_KEY", "APP_DIR"]);
  });
});

describe("unsandboxed environment inheritance", () => {
  const secrets = {
    ANTHROPIC_API_KEY: "fake-anthropic",
    OPENROUTER_API_KEY: "fake-openrouter",
    GITHUB_TOKEN: "fake-github",
    AWS_SECRET_ACCESS_KEY: "fake-aws",
    PALIZADE_LISTENER_TOKEN: "fake-palizade"
  };

  it.each(["win32", "linux", "darwin"] as const)("defaults old YAML to a minimal child environment on %s", (platform) => {
    const server = parseConfig("servers:\n  demo: { command: node }\n").servers.demo!;
    const hostEnv = { ...secrets, PATH: "fake-path", SSH_AUTH_SOCK: "fake-socket" };
    expect(buildLaunchPlan("demo", server, { platform, hostEnv }).env).toEqual({ PATH: "fake-path" });
    expect(server).toMatchObject({ inheritEnv: "minimal", passEnv: [] });
  });

  it.each(["win32", "linux", "darwin"] as const)("expands templates and passes only selected names on %s", (platform) => {
    const server = {
      command: "${APP_COMMAND}", args: ["${ARG_VALUE}"], passEnv: ["PROJECT_ENV", "UNSET_VAR", "PALIZADE_LISTENER_TOKEN"],
      env: { DECLARED: "fake-declared", RESOLVED: "${ARG_VALUE}", PATH: "fake-override", PALIZADE_EXPLICIT: "fake-reserved" }
    };
    const hostEnv = platform === "win32"
      ? { ...secrets, Path: "fake-path", project_env: "fake-selected", app_command: "node", arg_value: "fake-template", SystemRoot: "fake-root" }
      : { ...secrets, PATH: "fake-path", PROJECT_ENV: "fake-selected", APP_COMMAND: "node", ARG_VALUE: "fake-template", HOME: "fake-home" };
    const plan = buildLaunchPlan("demo", server, { platform, hostEnv });
    expect(plan).toMatchObject({ command: "node", args: ["fake-template"] });
    expect(plan.env).toEqual({ PATH: "fake-override", PROJECT_ENV: "fake-selected", DECLARED: "fake-declared", RESOLVED: "fake-template", ...(platform === "win32" ? { SystemRoot: "fake-root" } : { HOME: "fake-home" }) });
    const audit = describeLaunchForAudit(plan, server);
    expect(audit).toMatchObject({ envMode: "minimal", envKeys: Object.keys(plan.env).sort() });
    expect(JSON.stringify(audit)).not.toContain("fake-template");
  });

  it("allows explicit secrets and full mode while excluding Palizade variables", () => {
    const server = { command: "node", args: [], env: {}, inheritEnv: "full" as const };
    const plan = buildLaunchPlan("demo", server, { platform: "linux", hostEnv: secrets });
    expect(plan.env).toEqual({ ANTHROPIC_API_KEY: "fake-anthropic", OPENROUTER_API_KEY: "fake-openrouter", GITHUB_TOKEN: "fake-github", AWS_SECRET_ACCESS_KEY: "fake-aws" });
    expect(buildLaunchPlan("demo", { ...server, inheritEnv: "minimal", passEnv: ["GITHUB_TOKEN"] }, { platform: "linux", hostEnv: secrets }).env).toEqual({ GITHUB_TOKEN: "fake-github" });
    expect(describeLaunchForAudit(plan, server)).toMatchObject({ envMode: "full", envKeys: Object.keys(plan.env).sort() });
    expect(sandboxStatus({ demo: server }, "linux", secrets)[0]?.detail).toMatch(/WARNING.*env=full.*GITHUB_TOKEN/u);
    expect(sandboxStatus({ demo: { ...server, inheritEnv: "minimal", passEnv: ["GITHUB_TOKEN"] } }, "linux", secrets)[0]?.detail).toMatch(/env=minimal.*GITHUB_TOKEN/u);
  });

  it("prints one migration hint only when a minimal child exits with an error", async () => {
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      for (const [inheritEnv, code] of [["minimal", 1], ["full", 1], ["minimal", 0]] as const) {
        const { child } = await launchUpstream("demo", { command: process.execPath, args: ["-e", `process.exit(${code})`], env: {}, inheritEnv }, { resolveCommand: (command) => command });
        expect((await once(child, "close"))[0]).toBe(code);
      }
      const hints = stderr.mock.calls.filter(([message]) => String(message).includes("passEnv"));
      expect(hints).toHaveLength(1);
      expect(hints[0]?.[0]).toMatch(/inheritEnv: full/u);
    } finally {
      stderr.mockRestore();
    }
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
  const nodeDirectory = dirname(process.execPath);
  const npxShim = join(nodeDirectory, "npx.cmd");
  it.runIf(process.platform === "win32" && existsSync(npxShim))("starts the Windows Node npx shim without a shell", async () => {
    const { child } = await launchUpstream("npx", {
      command: npxShim,
      args: ["--version"],
      env: {}
    }, { resolveCommand: (command) => command });
    let stdout = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    const [code] = await once(child, "close");

    expect(code).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/u);
  });

  it.runIf(process.platform === "win32")("passes Windows npx arguments with spaces, quotes and shell characters intact", async () => {
    const cwd = await tempDir();
    const bin = join(cwd, "node_modules", "npm", "bin");
    await mkdir(bin, { recursive: true });
    await copyFile(process.execPath, join(cwd, "node.exe"));
    await writeFile(join(bin, "npx-cli.js"), "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n");
    const args = ["two words", 'say "hello"', "a&b", "a^b", "%PALIZADE_TEST_VAR%", 'space \\"quoted" & ^ %PALIZADE_TEST_VAR%'];
    const { child } = await launchUpstream("npx", {
      command: join(cwd, "npx.cmd"), args, cwd, env: {}
    }, { resolveCommand: (command) => command });
    let stdout = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    expect((await once(child, "close"))[0]).toBe(0);
    expect(JSON.parse(stdout)).toEqual(args);
  });

  it("rejects when the configured executable cannot be started", async () => {
    await expect(launchUpstream("missing", {
      command: "palizade-test-command-that-does-not-exist",
      args: [],
      env: {}
    }, { resolveCommand: (command) => command })).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("logs every spawn with masked arguments and no environment values", async () => {
    const events: AuditEvent[] = [];
    const audit = new AuditLogger([{ write: async (event) => { events.push(event); } }]);
    const { child, plan } = await launchUpstream("plain", {
      command: process.execPath,
      args: ["-e", "process.exit(0)", "--", "--api_key=sk-test-should-not-leak"],
      env: { SERVICE_PASSWORD: "hunter2hunter2" },
      sandbox: "none"
    }, { resolveCommand: (command) => command, audit, sessionId: "s1" });
    expect((await once(child, "close"))[0]).toBe(0);
    const spawn = events.find((event) => event.method === "process/spawn");
    const envKeys = Object.keys(plan.env).sort();
    expect(envKeys).toContain("SERVICE_PASSWORD");
    expect(spawn?.metadata?.spawn).toMatchObject({ sandbox: "none", envMode: "minimal", envKeys });
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
