import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { JsonlAuditSink, type AuditEvent } from "@palizade/audit";
import { loadConfig, LockfileStore, type PalizadeLock } from "@palizade/core";
import { SqliteTaintStore } from "@palizade/taint";

export interface StatusRow {
  name: string;
  transport: "stdio" | "http";
  era: string;
  command?: string;
  url?: string;
  trust: string;
  /** Protocol era last recorded in audit for this server, if any. */
  lastSeenEra?: string | undefined;
  lock: { state: "locked" | "unlocked"; tools: number; lastApprovedAt?: string | undefined };
  sandbox?: string | undefined;
}

export interface SessionStatus {
  session: string;
  quarantine?: { expiresAt: string; remainingTurns: number } | undefined;
  seenUntrusted: boolean;
  seenSensitive: boolean;
  ruleOfTwo: boolean;
}

export interface BlockSummary {
  ts: string;
  server?: string | undefined;
  tool?: string | undefined;
  method?: string | undefined;
  rule?: string | undefined;
  reason?: string | undefined;
}

export interface StatusReport {
  config: string;
  policy: string;
  policyHash: string;
  servers: StatusRow[];
  taintRecords: number;
  taintRecordsByKind: { normal: number; persistent: number };
  lockfile: string;
  sessions: { total: number; quarantined: SessionStatus[]; ruleOfTwo: SessionStatus[] };
  lastBlocks: BlockSummary[];
}

const MAX_LISTED_SESSIONS = 1000;
const LAST_BLOCKS = 10;

export async function buildStatus(configPath: string, now = Date.now()): Promise<StatusReport> {
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
  let counts: { normal: number; persistent: number };
  let sessions: SessionStatus[];
  try {
    counts = taintStore.recordCounts();
    sessions = taintStore.listSessions(MAX_LISTED_SESSIONS).map(({ key, state }) => {
      const quarantine = state.quarantine && state.quarantine.expiresAt > now && state.quarantine.remainingTurns > 0 ? state.quarantine : undefined;
      return {
        session: key,
        quarantine: quarantine ? { expiresAt: new Date(quarantine.expiresAt).toISOString(), remainingTurns: quarantine.remainingTurns } : undefined,
        seenUntrusted: state.seenUntrusted,
        seenSensitive: state.seenSensitive,
        ruleOfTwo: state.seenUntrusted && state.seenSensitive
      };
    });
  } finally {
    taintStore.close();
  }

  const lock: PalizadeLock = await new LockfileStore(config.lockfile).read().catch(() => ({ version: 1, servers: {} }));
  // shortcut: reads the whole JSONL audit file like `palizade audit`; switch to the SQLite sink's indexed query if audit files grow past tens of MB.
  const events = await new JsonlAuditSink(config.audit.jsonl).query({ limit: Number.MAX_SAFE_INTEGER }).catch((): AuditEvent[] => []);
  const lastEra = new Map<string, string>();
  for (const event of events) {
    const era = event.metadata?.era;
    if (event.server && typeof era === "string") lastEra.set(event.server, era);
  }

  const servers = Object.entries(config.servers).map(([name, server]): StatusRow => {
    const tools = Object.values(lock.servers[name]?.tools ?? {});
    const lastApprovedAt = tools.map((tool) => tool.approvedAt).sort().at(-1);
    return {
      name,
      transport: server.url ? "http" : "stdio",
      era: server.url ? (server.protocolVersion ?? "auto") : "stdio",
      ...(server.url
        ? { url: server.url }
        : server.command !== undefined
          ? { command: server.command }
          : { command: "<unset>" }),
      trust: server.trust,
      lastSeenEra: lastEra.get(name),
      lock: { state: tools.length > 0 ? "locked" : "unlocked", tools: tools.length, lastApprovedAt },
      sandbox: server.url ? undefined : typeof server.sandbox === "string" ? server.sandbox : server.sandbox?.type ?? "none"
    };
  });

  const lastBlocks = events.filter((event) => event.action === "block").slice(-LAST_BLOCKS).reverse().map((event): BlockSummary => ({
    ts: event.ts,
    server: event.server,
    tool: event.tool,
    method: event.method,
    rule: event.matched_rule?.id,
    reason: event.reason
  }));

  return {
    config: configPath,
    policy: config.policy,
    policyHash,
    servers,
    taintRecords: counts.normal + counts.persistent,
    taintRecordsByKind: counts,
    lockfile: config.lockfile,
    sessions: {
      total: sessions.length,
      quarantined: sessions.filter((session) => session.quarantine),
      ruleOfTwo: sessions.filter((session) => session.ruleOfTwo)
    },
    lastBlocks
  };
}

export function printStatus(report: StatusReport, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(`Config: ${report.config}`);
  console.log(`Policy: ${report.policy} (sha256:${report.policyHash})`);
  console.log(`Taint records: ${report.taintRecords} (normal ${report.taintRecordsByKind.normal}, persistent ${report.taintRecordsByKind.persistent})`);
  console.log("Servers:");
  for (const server of report.servers) {
    const target = server.transport === "http" ? `url=${server.url}` : `command=${server.command}`;
    const seen = server.lastSeenEra ? ` last seen ${server.lastSeenEra}` : "";
    const lock = server.lock.state === "locked" ? `locked ${server.lock.tools} tool(s)` : "UNLOCKED";
    const sandbox = server.sandbox ? ` sandbox=${server.sandbox}` : "";
    console.log(`  ${server.name}: ${server.transport} (era=${server.era}${seen}) [trust=${server.trust}] [${lock}]${sandbox} ${target}`);
  }
  console.log(`Sessions: ${report.sessions.total} stored, ${report.sessions.quarantined.length} quarantined, ${report.sessions.ruleOfTwo.length} with Rule of Two armed (untrusted + sensitive seen)`);
  for (const session of report.sessions.quarantined) {
    console.log(`  QUARANTINED ${session.session} until ${session.quarantine!.expiresAt} (${session.quarantine!.remainingTurns} sink turn(s) left)`);
  }
  for (const session of report.sessions.ruleOfTwo) {
    console.log(`  RULE OF TWO ${session.session}`);
  }
  console.log(report.lastBlocks.length > 0 ? `Last ${report.lastBlocks.length} block(s):` : "Last blocks: none");
  for (const block of report.lastBlocks) {
    console.log(`  ${block.ts} ${block.server ?? "-"} ${block.tool ?? block.method ?? "-"}${block.rule ? ` rule=${block.rule}` : ""}${block.reason ? `: ${block.reason}` : ""}`);
  }
}
