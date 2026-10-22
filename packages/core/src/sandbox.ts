import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { maskKnownSensitiveText } from "@palizade/detectors";
import { expandEnvTemplates, expandServerTemplates } from "./env-templates.js";

export const sandboxTypeSchema = z.enum(["none", "docker", "bubblewrap", "seatbelt"]);
export type SandboxType = z.infer<typeof sandboxTypeSchema>;

export const sandboxObjectSchema = z.object({
  type: sandboxTypeSchema.default("none"),
  image: z.string().min(1).optional(),
  writable: z.array(z.string().min(1)).default([]),
  network: z.enum(["none", "allowlist"]).default("none"),
  allowHosts: z.array(z.string().min(1)).default([]),
  passEnv: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/u, "passEnv entries must be environment variable names")).default([]),
  dockerNetwork: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/u, "dockerNetwork must be a docker network name").optional(),
  pidsLimit: z.number().int().min(16).max(65_536).default(512),
  memory: z.string().regex(/^\d+[bkmg]?$/iu, "memory must look like 512m or 2g").optional(),
  advisoryNetwork: z.boolean().default(false)
}).strict().superRefine((sandbox, ctx) => {
  if (sandbox.network === "allowlist" && sandbox.allowHosts.length === 0) {
    ctx.addIssue({ code: "custom", path: ["allowHosts"], message: "sandbox.network: allowlist needs at least one allowHosts entry; use network: none to block all egress." });
  }
  // Fail closed: an allowlist the server can route around must be an explicit, visible choice.
  if (isAdvisoryNetwork(sandbox) && !sandbox.advisoryNetwork) {
    ctx.addIssue({
      code: "custom",
      path: ["network"],
      message: sandbox.type === "docker"
        ? "network: allowlist with docker is only enforced on an internal network whose only route is the proxy; set dockerNetwork, or set advisoryNetwork: true to accept proxy-only filtering."
        : "network: allowlist with bubblewrap shares the host network, so the proxy is advisory; use seatbelt or docker with dockerNetwork, or set advisoryNetwork: true to accept it."
    });
  }
});

/** True when network: allowlist relies on the server honoring HTTP(S)_PROXY instead of an enforced route. */
export function isAdvisoryNetwork(sandbox: { type: string; network: string; dockerNetwork?: string | undefined }): boolean {
  if (sandbox.network !== "allowlist") return false;
  return (sandbox.type === "docker" && !sandbox.dockerNetwork) || sandbox.type === "bubblewrap";
}

/** `sandbox: docker` is shorthand for `sandbox: { type: docker }`. */
export const sandboxConfigSchema = z.union([sandboxTypeSchema, sandboxObjectSchema]);

export type SandboxConfig = z.infer<typeof sandboxObjectSchema>;
export type SandboxConfigInput = z.input<typeof sandboxConfigSchema>;

export const DEFAULT_DOCKER_IMAGE = "node:22-slim";
export const DOCKER_WORKDIR = "/workspace";

export interface LaunchServerConfig {
  command?: string | undefined;
  args: string[];
  cwd?: string | undefined;
  env: Record<string, string>;
  sandbox?: z.output<typeof sandboxConfigSchema> | undefined;
}

export interface LaunchPlan {
  command: string;
  args: string[];
  cwd: string | undefined;
  env: NodeJS.ProcessEnv;
  sandbox: SandboxType;
  /** Proxy URL the sandboxed server must use when network is allowlist. */
  proxyUrl?: string | undefined;
  /** `${NAME}` placeholders in command, args or env that had no value and no default. */
  missingEnv?: string[] | undefined;
}

export interface LaunchOptions {
  platform?: NodeJS.Platform;
  hostEnv?: NodeJS.ProcessEnv;
  /** host:port of the Palizade egress proxy, required when network is allowlist. */
  proxy?: { host: string; port: number; token?: string | undefined } | undefined;
  /** Resolves the upstream command on the host (Windows .cmd shims) for unsandboxed launches. */
  resolveCommand?: (command: string) => string;
}

export function normalizeSandbox(value: LaunchServerConfig["sandbox"]): SandboxConfig {
  if (value === undefined) return sandboxObjectSchema.parse({});
  if (typeof value === "string") return sandboxObjectSchema.parse({ type: value });
  return value;
}

export function sandboxPlatformError(type: SandboxType, platform: NodeJS.Platform): string | undefined {
  if (type === "none" || type === "docker") return undefined;
  if (type === "bubblewrap" && platform !== "linux") {
    return `sandbox: bubblewrap only runs on Linux (this host is ${platform}).${platform === "win32" ? " On Windows only sandbox: docker is available." : " Use sandbox: docker, or seatbelt on macOS."}`;
  }
  if (type === "seatbelt" && platform !== "darwin") {
    return `sandbox: seatbelt uses macOS sandbox-exec and only runs on macOS (this host is ${platform}).${platform === "win32" ? " On Windows only sandbox: docker is available." : " Use sandbox: docker or bubblewrap on Linux."}`;
  }
  return undefined;
}

export function assertSandboxSupported(serverName: string, server: LaunchServerConfig, platform: NodeJS.Platform = process.platform): SandboxConfig {
  const sandbox = normalizeSandbox(server.sandbox);
  const error = sandboxPlatformError(sandbox.type, platform);
  if (error) {
    throw new Error(`Server '${serverName}': ${error}`);
  }
  return sandbox;
}

export function buildLaunchPlan(serverName: string, server: LaunchServerConfig, options: LaunchOptions = {}): LaunchPlan {
  const hostEnv = options.hostEnv ?? process.env;
  const expanded = expandServerTemplates(server, hostEnv);
  const plan = buildExpandedLaunchPlan(serverName, expanded.server, hostEnv, options);
  return expanded.missing.length > 0 ? { ...plan, missingEnv: expanded.missing } : plan;
}

function buildExpandedLaunchPlan(serverName: string, server: LaunchServerConfig, hostEnv: NodeJS.ProcessEnv, options: LaunchOptions): LaunchPlan {
  const platform = options.platform ?? process.platform;
  const sandbox = assertSandboxSupported(serverName, server, platform);
  if (!server.command) {
    throw new Error(`Server '${serverName}' has no command; only stdio servers can be launched.`);
  }
  if (sandbox.network === "allowlist" && sandbox.type !== "none" && !options.proxy) {
    throw new Error(`Server '${serverName}': sandbox.network allowlist needs the Palizade egress proxy to be running.`);
  }
  const cwd = server.cwd ?? process.cwd();

  if (sandbox.type === "none") {
    const resolveCommand = options.resolveCommand ?? ((command: string) => command);
    return { command: resolveCommand(server.command), args: server.args, cwd: server.cwd, env: { ...hostEnv, ...server.env }, sandbox: "none" };
  }

  const envKeys = [...new Set([...Object.keys(server.env), ...sandbox.passEnv])].sort();
  const passedValues = Object.fromEntries(sandbox.passEnv.filter((key) => hostEnv[key] !== undefined).map((key) => [key, hostEnv[key]!]));
  const proxyAuth = options.proxy?.token ? `palizade:${options.proxy.token}@` : "";
  const proxyUrl = options.proxy ? `http://${proxyAuth}${options.proxy.host}:${options.proxy.port}` : undefined;

  if (sandbox.type === "docker") {
    for (const path of [cwd, ...sandbox.writable]) {
      if (path.includes(",")) {
        throw new Error(`Server '${serverName}': docker bind mount paths cannot contain commas (${path}).`);
      }
    }
    const containerProxy = options.proxy ? `http://${proxyAuth}host.docker.internal:${options.proxy.port}` : undefined;
    const args = [
      "run", "--rm", "-i", "--init",
      "--security-opt", "no-new-privileges",
      "--cap-drop", "ALL",
      "--read-only",
      "--tmpfs", "/tmp:rw,nosuid,size=256m",
      "--pids-limit", String(sandbox.pidsLimit),
      ...(sandbox.memory ? ["--memory", sandbox.memory] : []),
      ...dockerNetworkArgs(sandbox, platform),
      "--mount", `type=bind,source=${cwd},target=${DOCKER_WORKDIR},readonly`,
      ...dockerWritableMounts(sandbox.writable, cwd).flatMap((mount) => ["--mount", `type=bind,source=${mount.host},target=${mount.container}`]),
      "-w", DOCKER_WORKDIR,
      "-e", "HOME=/tmp",
      ...(containerProxy ? ["-e", `HTTP_PROXY=${containerProxy}`, "-e", `HTTPS_PROXY=${containerProxy}`, "-e", `http_proxy=${containerProxy}`, "-e", `https_proxy=${containerProxy}`, "-e", "NO_PROXY="] : []),
      // Values never appear on the command line: docker reads each listed key from its own environment.
      ...envKeys.flatMap((key) => ["-e", key]),
      sandbox.image ?? DEFAULT_DOCKER_IMAGE,
      server.command,
      ...server.args
    ];
    return {
      command: "docker",
      args,
      cwd,
      env: { ...hostEnv, ...passedValues, ...server.env },
      sandbox: "docker",
      proxyUrl: containerProxy
    };
  }

  const childEnv: NodeJS.ProcessEnv = {
    ...(hostEnv.PATH ? { PATH: hostEnv.PATH } : {}),
    HOME: sandbox.type === "bubblewrap" ? "/tmp" : hostEnv.HOME,
    ...passedValues,
    ...server.env,
    ...(proxyUrl ? { HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl } : {})
  };

  if (sandbox.type === "bubblewrap") {
    const writable = sandbox.writable.map((entry) => resolve(cwd, splitWritable(entry).host));
    const args = [
      "--die-with-parent",
      "--new-session",
      "--unshare-all",
      ...(sandbox.network === "allowlist" ? ["--share-net"] : []),
      "--cap-drop", "ALL",
      ...["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc/alternatives", "/etc/ssl", "/etc/ca-certificates", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/opt", "/nix"]
        .flatMap((path) => ["--ro-bind-try", path, path]),
      ...commandDirBinds(server.command),
      "--proc", "/proc",
      "--dev", "/dev",
      "--tmpfs", "/tmp",
      "--ro-bind", cwd, cwd,
      ...writable.flatMap((path) => ["--bind", path, path]),
      "--chdir", cwd,
      "--",
      server.command,
      ...server.args
    ];
    return { command: "bwrap", args, cwd, env: childEnv, sandbox: "bubblewrap", proxyUrl };
  }

  const writable = sandbox.writable.map((entry) => resolve(cwd, splitWritable(entry).host));
  const profile = seatbeltProfile({ writable, proxyPort: sandbox.network === "allowlist" ? options.proxy?.port : undefined });
  return {
    command: "/usr/bin/sandbox-exec",
    args: ["-p", profile, server.command, ...server.args],
    cwd,
    env: childEnv,
    sandbox: "seatbelt",
    proxyUrl
  };
}

export function seatbeltProfile(input: { writable: string[]; proxyPort?: number | undefined }): string {
  const quote = (path: string): string => `"${path.replace(/\\/gu, "\\\\").replace(/"/gu, "\\\"")}"`;
  return [
    "(version 1)",
    "(deny default)",
    "(allow process-exec)",
    "(allow process-fork)",
    "(allow signal (target same-sandbox))",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow ipc-posix-shm)",
    // shortcut: seatbelt allows reads everywhere (node and npm read across the system), restrict reads once a per-runtime read list is maintained.
    "(allow file-read*)",
    `(allow file-write* (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr") (subpath "/private/tmp") (subpath "/private/var/folders")${input.writable.map((path) => ` (subpath ${quote(path)})`).join("")})`,
    ...(input.proxyPort ? [`(allow network-outbound (remote tcp "localhost:${input.proxyPort}"))`] : [])
  ].join("\n");
}

export interface SandboxStatusRow {
  server: string;
  sandbox: SandboxType;
  status: "sandboxed" | "unsandboxed" | "unsupported" | "remote";
  detail: string;
}

export function sandboxStatus(servers: Record<string, LaunchServerConfig & { url?: string | undefined }>, platform: NodeJS.Platform = process.platform): SandboxStatusRow[] {
  return Object.entries(servers).map(([server, config]) => {
    if (config.url) {
      return { server, sandbox: "none", status: "remote", detail: "remote url server; nothing is spawned locally" };
    }
    const sandbox = normalizeSandbox(config.sandbox);
    const error = sandboxPlatformError(sandbox.type, platform);
    if (error) {
      return { server, sandbox: sandbox.type, status: "unsupported", detail: error };
    }
    if (sandbox.type === "none") {
      return { server, sandbox: "none", status: "unsandboxed", detail: "runs with your user's full file, network and environment access; consider sandbox: docker" };
    }
    const network = sandbox.network === "none" ? "no network" : `network allowlist: ${sandbox.allowHosts.join(", ")}${isAdvisoryNetwork(sandbox) ? " (ADVISORY: not enforced, the server can bypass the proxy)" : ""}`;
    return { server, sandbox: sandbox.type, status: "sandboxed", detail: `${network}; writable: ${sandbox.writable.length > 0 ? sandbox.writable.join(", ") : "none"}` };
  });
}

export interface SpawnAuditRecord {
  command: string;
  args: string[];
  cwd?: string | undefined;
  sandbox: SandboxType;
  envKeys: string[];
  proxy?: string | undefined;
}

/** Spawn description for the audit log: environment values are never included and secret-looking arguments are masked. */
export function describeLaunchForAudit(plan: LaunchPlan, server: LaunchServerConfig): SpawnAuditRecord {
  // Mask the values the server actually receives, so expanded `${NAME}` secrets are covered too.
  const secretValues = Object.entries(server.env)
    .map(([key, value]) => plan.env[key] ?? expandEnvTemplates(value).value)
    .filter((value) => value.length >= 4);
  const maskArg = (arg: string): string => {
    let masked = maskKnownSensitiveText(arg);
    for (const value of secretValues) {
      masked = masked.split(value).join("[REDACTED:env]");
    }
    masked = masked.replace(/\/\/palizade:[^@\s]+@/gu, "//palizade:[REDACTED]@");
    masked = masked.replace(/((?:token|secret|password|passwd|api[_-]?key|auth|credential)[A-Za-z0-9_-]*\s*[=:]\s*)[^\s,;&]+/giu, "$1[REDACTED]");
    return plan.sandbox === "seatbelt" && arg.startsWith("(version 1)") ? "[seatbelt profile]" : masked;
  };
  const envKeys = plan.sandbox === "none"
    ? Object.keys(server.env).sort()
    : [...new Set([...Object.keys(server.env), ...normalizeSandbox(server.sandbox).passEnv])].sort();
  return {
    command: maskArg(plan.command),
    args: plan.args.map(maskArg),
    cwd: plan.cwd,
    sandbox: plan.sandbox,
    envKeys,
    proxy: plan.proxyUrl ? maskArg(plan.proxyUrl) : undefined
  };
}

function dockerNetworkArgs(sandbox: SandboxConfig, platform: NodeJS.Platform): string[] {
  if (sandbox.network === "none") {
    return ["--network", "none"];
  }
  // Without dockerNetwork this is advisory; config validation rejects it unless advisoryNetwork: true.
  return [
    "--network", sandbox.dockerNetwork ?? "bridge",
    ...(platform === "linux" ? ["--add-host", "host.docker.internal:host-gateway"] : [])
  ];
}

interface DockerMount {
  host: string;
  container: string;
}

export function dockerWritableMounts(entries: string[], cwd: string): DockerMount[] {
  return entries.map((entry, index) => {
    const { host, container } = splitWritable(entry);
    const hostPath = resolve(cwd, host);
    if (container) {
      return { host: hostPath, container };
    }
    const rel = relative(cwd, hostPath);
    if (rel === "") {
      return { host: hostPath, container: DOCKER_WORKDIR };
    }
    if (!rel.startsWith("..") && !isAbsolute(rel)) {
      return { host: hostPath, container: `${DOCKER_WORKDIR}/${rel.split(sep).join("/")}` };
    }
    return { host: hostPath, container: `/mnt/palizade/${index}-${basename(hostPath)}` };
  });
}

/** `host` or `host::/container/path`. A double colon keeps Windows drive letters unambiguous. */
function splitWritable(entry: string): { host: string; container?: string | undefined } {
  const marker = entry.indexOf("::");
  if (marker === -1) return { host: entry };
  return { host: entry.slice(0, marker), container: entry.slice(marker + 2) };
}

function commandDirBinds(command: string): string[] {
  if (isAbsolute(command)) {
    const dir = resolve(command, "..");
    return ["--ro-bind-try", dir, dir];
  }
  // shortcut: relative commands rely on PATH entries under /usr, /bin, /opt or /nix being bound; version-manager installs in $HOME (nvm, volta) need an absolute command path.
  return [];
}
