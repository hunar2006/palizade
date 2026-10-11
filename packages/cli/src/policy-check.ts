import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadConfig, LockfileStore, type PalizadeConfig, type PalizadeLock } from "@palizade/core";
import { checkPolicy, type PolicyCheckContext, type PolicyFinding } from "@palizade/policy";

export interface PolicyCheckReport {
  file: string;
  rules: number;
  errors: number;
  warnings: number;
  referencesChecked: boolean;
  note?: string | undefined;
  findings: PolicyFinding[];
}

export async function runPolicyCheck(options: { file?: string | undefined; configPath: string }): Promise<PolicyCheckReport> {
  let config: PalizadeConfig | undefined;
  let note: string | undefined;
  try {
    config = await loadConfig(options.configPath);
  } catch (error) {
    if (!options.file) throw error;
    note = (error as NodeJS.ErrnoException).code === "ENOENT"
      ? `No config at ${resolve(options.configPath)}; server and tool references were not checked.`
      : `Config ${resolve(options.configPath)} did not load; server and tool references were not checked. Run 'palizade doctor' for details.`;
  }
  const file = options.file ? resolve(options.file) : config!.policy;
  const raw = await readFile(file, "utf8");
  const context = config ? await referenceContext(config) : {};
  const result = checkPolicy(raw, file, context);
  return {
    file,
    rules: result.policy?.rules.length ?? 0,
    errors: result.findings.filter((finding) => finding.level === "error").length,
    warnings: result.findings.filter((finding) => finding.level === "warning").length,
    referencesChecked: config !== undefined,
    note,
    findings: result.findings
  };
}

async function referenceContext(config: PalizadeConfig): Promise<PolicyCheckContext> {
  const lock: PalizadeLock = await new LockfileStore(config.lockfile).read().catch(() => ({ version: 1, servers: {} }));
  const toolsByServer: Record<string, string[]> = {};
  for (const [name, server] of Object.entries(config.servers)) {
    toolsByServer[name] = [...new Set([
      ...Object.keys(lock.servers[name]?.tools ?? {}),
      ...Object.keys(server.toolClasses),
      ...Object.keys(server.toolCapabilities),
      ...Object.keys(server.argumentRoles),
      ...Object.keys(server.sensitiveTools)
    ])];
  }
  return { servers: Object.keys(config.servers), toolsByServer };
}

export function formatPolicyCheck(report: PolicyCheckReport): string {
  const lines: string[] = [];
  if (report.note) lines.push(report.note);
  const summary = report.errors === 0 && report.warnings === 0
    ? `${report.file}: OK (${report.rules} rule${report.rules === 1 ? "" : "s"})`
    : `${report.file}: ${report.errors} error${report.errors === 1 ? "" : "s"}, ${report.warnings} warning${report.warnings === 1 ? "" : "s"}`;
  lines.push(summary);
  for (const finding of report.findings) {
    lines.push(`  ${finding.level.padEnd(7)} ${finding.path}${finding.line ? ` (line ${finding.line})` : ""} [${finding.check}]: ${finding.message}`);
    lines.push(`          fix: ${finding.hint}`);
  }
  return lines.join("\n");
}
