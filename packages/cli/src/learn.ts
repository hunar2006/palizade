import type { AuditEvent } from "@palizade/audit";

export interface LearnOptions {
  since: Date;
  /** Existing palizade.yaml overrides, so the draft only lists what is new. */
  existingToolClasses?: Record<string, Record<string, string>> | undefined;
}

export interface LearnDraft {
  events: number;
  servers: Record<string, { toolClasses: Record<string, { toolClass: string; calls: number }> }>;
  allowlist: { hosts: Array<{ value: string; calls: number }>; emails: Array<{ value: string; calls: number }> };
  notSuggested: Array<{ value: string; reason: string }>;
  truncated: boolean;
}

const MAX_ENTRIES = 200;
const ALLOWED_ACTIONS = new Set(["allow", "log_only", "sanitize", "redact_spans", "redact_secrets"]);

export function learnFromAudit(events: AuditEvent[], options: LearnOptions): LearnDraft {
  const relevant = events.filter((event) => new Date(event.ts) >= options.since && event.direction === "request" && event.method === "tools/call" && event.server && event.tool);
  const classes = new Map<string, Map<string, Map<string, number>>>();
  const destinations = new Map<string, { kind: "hosts" | "emails"; allowed: number; blocked: number; tainted: number; alreadyAllowed: boolean }>();

  for (const event of relevant) {
    const toolClass = typeof event.metadata?.toolClass === "string" ? event.metadata.toolClass : "unknown";
    const byTool = classes.get(event.server!) ?? new Map<string, Map<string, number>>();
    const counts = byTool.get(event.tool!) ?? new Map<string, number>();
    counts.set(toolClass, (counts.get(toolClass) ?? 0) + 1);
    byTool.set(event.tool!, counts);
    classes.set(event.server!, byTool);

    const destination = event.metadata?.destination as { allowed?: boolean; hosts?: unknown; emailRecipients?: unknown } | undefined;
    if (!destination) continue;
    const allowed = ALLOWED_ACTIONS.has(event.action) || event.metadata?.approved === true;
    for (const [kind, values] of [["hosts", destination.hosts], ["emails", destination.emailRecipients]] as const) {
      if (!Array.isArray(values)) continue;
      for (const value of values) {
        if (typeof value !== "string" || value.length === 0) continue;
        const key = `${kind}:${value.toLowerCase()}`;
        const entry = destinations.get(key) ?? { kind, allowed: 0, blocked: 0, tainted: 0, alreadyAllowed: false };
        if (allowed) entry.allowed += 1; else entry.blocked += 1;
        if (event.taint_ids.length > 0) entry.tainted += 1;
        if (destination.allowed === true) entry.alreadyAllowed = true;
        destinations.set(key, entry);
      }
    }
  }

  let truncated = false;
  const servers: LearnDraft["servers"] = {};
  for (const [server, byTool] of [...classes].sort(([left], [right]) => left.localeCompare(right))) {
    const toolClasses: Record<string, { toolClass: string; calls: number }> = {};
    for (const [tool, counts] of [...byTool].sort(([left], [right]) => left.localeCompare(right))) {
      if (options.existingToolClasses?.[server]?.[tool] !== undefined) continue;
      if (Object.keys(toolClasses).length >= MAX_ENTRIES) { truncated = true; break; }
      const [toolClass] = [...counts].sort((left, right) => right[1] - left[1])[0]!;
      toolClasses[tool] = { toolClass, calls: [...counts.values()].reduce((sum, count) => sum + count, 0) };
    }
    if (Object.keys(toolClasses).length > 0) servers[server] = { toolClasses };
  }

  const allowlist: LearnDraft["allowlist"] = { hosts: [], emails: [] };
  const notSuggested: LearnDraft["notSuggested"] = [];
  for (const [key, entry] of [...destinations].sort(([left], [right]) => left.localeCompare(right))) {
    const value = key.slice(key.indexOf(":") + 1);
    if (entry.alreadyAllowed) continue;
    if (entry.tainted > 0) { notSuggested.push({ value, reason: `${entry.tainted} call(s) carried tainted data` }); continue; }
    if (entry.allowed === 0) { notSuggested.push({ value, reason: `only seen in ${entry.blocked} blocked or denied call(s)` }); continue; }
    if (allowlist[entry.kind].length >= MAX_ENTRIES) { truncated = true; continue; }
    allowlist[entry.kind].push({ value, calls: entry.allowed });
  }

  return { events: relevant.length, servers, allowlist, notSuggested: notSuggested.slice(0, MAX_ENTRIES), truncated };
}

export function formatLearnDraft(draft: LearnDraft, since: Date): string {
  const lines = [
    `# Draft from 'palizade learn --from-audit': ${draft.events} tools/call event(s) since ${since.toISOString()}.`,
    "# Review every entry before copying it into palizade.yaml. Palizade did not write any file."
  ];
  const serverNames = Object.keys(draft.servers);
  if (serverNames.length > 0) {
    lines.push("servers:");
    for (const server of serverNames) {
      lines.push(`  ${scalar(server)}:`, "    toolClasses:");
      for (const [tool, observed] of Object.entries(draft.servers[server]!.toolClasses)) {
        const note = observed.toolClass === "unknown" ? "; classify as source, sink or pure" : "";
        lines.push(`      ${scalar(tool)}: ${observed.toolClass}  # ${observed.calls} call(s)${note}`);
      }
    }
  }
  if (draft.allowlist.hosts.length > 0 || draft.allowlist.emails.length > 0) {
    lines.push("egress:", "  allowlist:");
    for (const kind of ["hosts", "emails"] as const) {
      if (draft.allowlist[kind].length === 0) continue;
      lines.push(`    ${kind}:`);
      for (const entry of draft.allowlist[kind]) lines.push(`      - ${scalar(entry.value)}  # ${entry.calls} allowed call(s)`);
    }
  }
  if (draft.notSuggested.length > 0) {
    lines.push("# Not suggested:");
    for (const entry of draft.notSuggested) lines.push(`#   ${entry.value}: ${entry.reason}`);
  }
  if (serverNames.length === 0 && draft.allowlist.hosts.length === 0 && draft.allowlist.emails.length === 0) lines.push("# Nothing new to suggest.");
  if (draft.truncated) lines.push(`# Truncated to ${MAX_ENTRIES} entries per list.`);
  return `${lines.join("\n")}\n`;
}

function scalar(value: string): string {
  return /^[A-Za-z0-9_][A-Za-z0-9_.@*/-]*$/u.test(value) && !/^(true|false|null|yes|no|on|off|~)$/iu.test(value) ? value : JSON.stringify(value);
}
