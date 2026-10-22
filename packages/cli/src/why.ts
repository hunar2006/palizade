import type { AuditEvent } from "@palizade/audit";

export interface Explanation {
  ts: string;
  action: string;
  server?: string | undefined;
  tool?: string | undefined;
  rule?: string | undefined;
  summary: string;
  details: string[];
  fixes: string[];
}

interface Advice {
  match: RegExp;
  summary: string;
  fixes: (event: AuditEvent, meta: Record<string, unknown>) => string[];
}

const lockApprove = (event: AuditEvent) => `If the change is expected: palizade lock diff ${event.server ?? "<server>"} then palizade lock approve ${event.server ?? "<server>"}`;

// Most specific patterns first.
const ADVICE: Advice[] = [
  {
    match: /unknown-tool/u,
    summary: "Palizade could not tell whether this tool only reads or also changes something, and the server is not trusted.",
    fixes: (event) => [
      `Check how it was classified: palizade tools ${event.server ?? ""}`.trim(),
      `If you know what it does, set servers.${event.server ?? "<server>"}.toolClasses.${event.tool ?? "<tool>"} to source, sink or pure in palizade.yaml`
    ]
  },
  {
    match: /tainted-destination|tainted-egress-destination/u,
    summary: "The destination (a url, host, email address, channel or repository) was copied from content an untrusted tool returned. This is how injected instructions usually send data out.",
    fixes: () => [
      "If you asked for this destination yourself, approve it when prompted (the interactive preset asks instead of blocking), or run the action directly.",
      "Allowlisting does not override this rule, because the destination still came from untrusted content."
    ]
  },
  {
    match: /lookalike-destination/u,
    summary: "The destination looks like a well known host with a small change, a common phishing pattern.",
    fixes: () => ["Check the exact spelling of the host. If it is really yours, add it with palizade allow host <host>."]
  },
  {
    match: /new-destination/u,
    summary: "Egress is in allowlist_only mode and this destination is not on the allowlist.",
    fixes: (_event, meta) => {
      const destination = meta.destination as { hosts?: string[]; emailRecipients?: string[] } | undefined;
      const hosts = destination?.hosts ?? [];
      const emails = destination?.emailRecipients ?? [];
      return [...hosts.map((host) => `palizade allow host ${host}`), ...emails.map((email) => `palizade allow email ${email}`), "Or list it under egress.allowlist in palizade.yaml."];
    }
  },
  {
    match: /secret|sensitive-into|sensitive-network|redact-pii/u,
    summary: "The arguments contain a secret, personal data, or data from a sensitive source, headed somewhere outside.",
    fixes: () => ["Remove the secret from the request. If the destination is meant to receive it, allowlist that destination and mark the server trusted only if you control it."]
  },
  {
    match: /rule-of-two/u,
    summary: "This session has read both untrusted content and sensitive data, so any outbound action needs a human check.",
    fixes: () => ["Approve the call if it is what you asked for, or start a new session: palizade session reset"]
  },
  {
    match: /delete-after-untrusted/u,
    summary: "This session has read untrusted content, and deleting data cannot be undone.",
    fixes: () => ["Approve the delete if you asked for it."]
  },
  {
    match: /quarantine/u,
    summary: "The session is quarantined after a blocked exfiltration attempt or a strongly suspicious tool result.",
    fixes: () => ["See the earlier block with palizade why --all, then clear it with palizade session reset once you are satisfied."]
  },
  {
    match: /split-match/u,
    summary: "Pieces of a secret or tainted value were spread across several outbound calls to the same place.",
    fixes: () => ["Approve only if you expected this data to go there."]
  },
  {
    match: /temporal/u,
    summary: "A tool recently returned text that looked like an instruction to the agent, so outbound actions need approval for a few turns.",
    fixes: () => ["Approve if the action is yours; the gate expires on its own."]
  },
  {
    match: /tainted-sink|tainted-memory|tainted-shell|tainted-critical/u,
    summary: "Text that an untrusted tool returned was copied into the arguments of an action that changes something.",
    fixes: () => ["Check the tainted argument below. If the data is meant to flow there, approve it or classify the source tool as trusted content."]
  },
  {
    match: /critical-path/u,
    summary: "The call writes to a file that controls agents, CI, git hooks or shell startup.",
    fixes: () => ["Approve after reading the diff Palizade shows with the prompt."]
  },
  {
    match: /lock-drift|unapproved-tool-metadata/u,
    summary: "The server's tool list or descriptions changed since you approved them.",
    fixes: (event) => [lockApprove(event)]
  },
  {
    match: /poisoned-tool-metadata|shadowing|name-collision|hidden-unicode/u,
    summary: "A tool description or schema looked like it was trying to instruct the agent, hide text, or impersonate another server's tool.",
    fixes: (event) => [`Inspect it with palizade lock diff ${event.server ?? "<server>"} before trusting this server.`]
  },
  {
    match: /sampling/u,
    summary: "The server asked to use your model (sampling), which Palizade denies by default.",
    fixes: () => ["Only allow sampling for servers you fully trust, with a policy rule for that server."]
  },
  {
    match: /elicitation/u,
    summary: "The server asked you for input through the agent.",
    fixes: () => ["Answer only if you expected the question."]
  },
  {
    match: /rate-limited|looping/u,
    summary: "The same kind of action repeated faster or more often than the session limits allow.",
    fixes: () => ["Approve if the repetition is intended, or raise limits in palizade.yaml."]
  }
];

export function explainEvent(event: AuditEvent): Explanation {
  const meta = (event.metadata ?? {}) as Record<string, unknown>;
  const rule = event.matched_rule?.id;
  const advice = rule ? ADVICE.find((entry) => entry.match.test(rule)) : undefined;
  const details: string[] = [];
  if (meta.toolClass) {
    const reasons = Array.isArray(meta.classificationReasons) ? ` (${(meta.classificationReasons as string[]).join(", ")})` : "";
    details.push(`tool class: ${String(meta.toolClass)}${reasons}`);
  }
  if (Array.isArray(meta.capabilities) && meta.capabilities.length > 0) details.push(`capabilities: ${(meta.capabilities as string[]).join(", ")}`);
  if (Array.isArray(meta.taintedArgumentRoles) && meta.taintedArgumentRoles.length > 0) details.push(`tainted arguments: ${(meta.taintedArgumentRoles as string[]).join(", ")}`);
  const sources = Array.isArray(meta.taintSources) ? meta.taintSources as Array<{ server?: string; tool?: string }> : [];
  if (sources.length > 0) details.push(`tainted data came from: ${[...new Set(sources.map((source) => `${source.server ?? "?"}/${source.tool ?? "?"}`))].join(", ")}`);
  const destination = meta.destination as { hosts?: string[]; emailRecipients?: string[] } | undefined;
  const targets = [...(destination?.hosts ?? []), ...(destination?.emailRecipients ?? [])];
  if (targets.length > 0) details.push(`destination: ${targets.join(", ")}`);
  if (event.detector?.score) details.push(`detector score: ${event.detector.score.toFixed(2)}${event.detector.labels.length ? ` (${event.detector.labels.join(", ")})` : ""}`);
  return {
    ts: event.ts,
    action: event.action,
    server: event.server,
    tool: event.tool ?? event.method,
    rule,
    summary: advice?.summary ?? event.reason ?? "No explanation is recorded for this rule.",
    details,
    fixes: advice ? advice.fixes(event, meta).filter(Boolean) : []
  };
}

export function formatExplanation(explanation: Explanation): string {
  const lines = [
    `${explanation.ts}  ${explanation.action.toUpperCase()}  ${explanation.server ?? "-"}/${explanation.tool ?? "-"}${explanation.rule ? `  [${explanation.rule}]` : ""}`,
    `  Why: ${explanation.summary}`
  ];
  for (const detail of explanation.details) lines.push(`  - ${detail}`);
  if (explanation.fixes.length > 0) {
    lines.push("  What you can do:");
    for (const fix of explanation.fixes) lines.push(`    ${fix}`);
  }
  return lines.join("\n");
}

/** Decisions worth explaining: anything that stopped, changed or paused a call. */
export function isInteresting(event: AuditEvent): boolean {
  return ["block", "require_approval", "sanitize", "redact_secrets"].includes(event.action) || (event.metadata as { approved?: boolean } | undefined)?.approved === false;
}
