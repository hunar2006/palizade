import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { loadConfig } from "@palizade/core";
import { SqliteTaintStore } from "@palizade/taint";

export interface StatusRow {
  name: string;
  transport: "stdio" | "http";
  era: string;
  command?: string;
  url?: string;
  trust: string;
}

export interface StatusReport {
  config: string;
  policy: string;
  policyHash: string;
  servers: StatusRow[];
  taintRecords: number;
}

export async function buildStatus(configPath: string): Promise<StatusReport> {
  const config = await loadConfig(configPath);
  const policyRaw = await readFile(config.policy, "utf8");
  const policyHash = createHash("sha256").update(policyRaw).digest("hex").slice(0, 16);
  const taintStore = new SqliteTaintStore(config.taint.sqlite, {
    scope: config.taint.scope,
    profileId: config.taint.profileId,
    keyPath: config.taint.keyPath,
    ttlMs: config.taint.ttlMs,
    ...(process.env.PALIZADE_RUN_ID ? { runId: process.env.PALIZADE_RUN_ID } : {})
  });
  const taintRecords = taintStore.all().length;
  taintStore.close();
  const servers = Object.entries(config.servers).map(([name, server]): StatusRow => ({
    name,
    transport: server.url ? "http" : "stdio",
    era: server.url ? (server.protocolVersion ?? "auto") : "stdio",
    ...(server.url
      ? { url: server.url }
      : server.command !== undefined
        ? { command: server.command }
        : { command: "<unset>" }),
    trust: server.trust
  }));
  return {
    config: configPath,
    policy: config.policy,
    policyHash,
    servers,
    taintRecords
  };
}

export function printStatus(report: StatusReport, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(`Config: ${report.config}`);
  console.log(`Policy: ${report.policy} (sha256:${report.policyHash})`);
  console.log(`Taint records: ${report.taintRecords}`);
  console.log("Servers:");
  for (const server of report.servers) {
    const target = server.transport === "http" ? `url=${server.url}` : `command=${server.command}`;
    console.log(`  ${server.name}: ${server.transport} (era=${server.era}) [trust=${server.trust}] ${target}`);
  }
}
