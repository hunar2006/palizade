import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { AuditLogger } from "@palizade/audit";
import { EgressProxy } from "./egress-proxy.js";
import { assertSandboxSupported, buildLaunchPlan, describeLaunchForAudit, type LaunchPlan, type LaunchServerConfig } from "./sandbox.js";

export interface LaunchContext {
  resolveCommand: (command: string) => string;
  audit?: AuditLogger | undefined;
  sessionId?: string | undefined;
  platform?: NodeJS.Platform | undefined;
}

export interface LaunchedUpstream {
  child: ChildProcessWithoutNullStreams;
  plan: LaunchPlan;
}

export async function launchUpstream(serverName: string, server: LaunchServerConfig, context: LaunchContext): Promise<LaunchedUpstream> {
  const platform = context.platform ?? process.platform;
  const sandbox = assertSandboxSupported(serverName, server, platform);
  const sessionId = context.sessionId ?? `spawn_${randomBytes(6).toString("hex")}`;

  let proxy: EgressProxy | undefined;
  let proxyAddress: { host: string; port: number; token: string } | undefined;
  if (sandbox.type !== "none" && sandbox.network === "allowlist") {
    // shortcut: on Linux, docker containers reach the host through the docker bridge, so the proxy listens on all interfaces behind a per-launch credential; bind to the bridge address once it is discoverable without shelling out to docker.
    const bindHost = sandbox.type === "docker" && platform === "linux" ? "0.0.0.0" : "127.0.0.1";
    const token = randomBytes(18).toString("hex");
    proxy = new EgressProxy({
      allowHosts: sandbox.allowHosts,
      host: bindHost,
      token,
      onEvent: (event) => {
        void context.audit?.write({
          session: sessionId,
          server: serverName,
          direction: "request",
          method: "sandbox/egress",
          action: event.allowed ? "allow" : "block",
          reason: event.allowed ? "sandbox egress to allowlisted host" : "sandbox egress to a host outside sandbox.allowHosts",
          metadata: { sandboxEgress: event }
        }).catch(() => undefined);
      }
    });
    const bound = await proxy.start();
    proxyAddress = { host: bound.host === "0.0.0.0" ? "127.0.0.1" : bound.host, port: bound.port, token };
  }

  try {
    const plan = buildLaunchPlan(serverName, server, { platform, proxy: proxyAddress, resolveCommand: context.resolveCommand });
    if (plan.missingEnv?.length) {
      process.stderr.write(`[palizade:${serverName}] environment variables not set, left as written: ${plan.missingEnv.join(", ")}\n`);
    }
    if (context.audit) {
      await context.audit.write({
        session: sessionId,
        server: serverName,
        direction: "internal",
        method: "process/spawn",
        action: "log_only",
        reason: plan.sandbox === "none" ? "spawned upstream server without a sandbox" : `spawned upstream server in ${plan.sandbox} sandbox`,
        metadata: { spawn: describeLaunchForAudit(plan, server) }
      });
    }
    const child = spawn(plan.command, plan.args, {
      cwd: plan.cwd,
      env: plan.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true
    });
    if (proxy) {
      const activeProxy = proxy;
      child.once("exit", () => { void activeProxy.close(); });
      child.once("error", () => { void activeProxy.close(); });
    }
    return { child, plan };
  } catch (error) {
    await proxy?.close();
    throw error;
  }
}
