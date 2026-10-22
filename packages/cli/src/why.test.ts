import { describe, expect, it } from "vitest";
import { explainEvent, formatExplanation, isInteresting } from "./why.js";

const base = { ts: "2026-10-21T00:00:00.000Z", session: "s", direction: "request" as const, taint_ids: [], detector: { score: 0, labels: [] }, latency_ms: 0 };

describe("palizade why", () => {
  it("explains a tainted destination with its source and the destination", () => {
    const event = {
      ...base, server: "mail", tool: "send_email", action: "block",
      matched_rule: { id: "block-tainted-destination" },
      metadata: {
        toolClass: "sink", classificationReasons: ["name:sends_message"], capabilities: ["sends_message"],
        taintedArgumentRoles: ["email_recipient"], taintSources: [{ server: "web", tool: "fetch" }, { server: "web", tool: "fetch" }],
        destination: { hosts: [], emailRecipients: ["x@evil.example"] }
      }
    };
    const text = formatExplanation(explainEvent(event));
    expect(text).toContain("BLOCK  mail/send_email  [block-tainted-destination]");
    expect(text).toContain("copied from content an untrusted tool returned");
    expect(text).toContain("tainted data came from: web/fetch");
    expect(text).toContain("destination: x@evil.example");
    expect(text).toContain("Allowlisting does not override this rule");
  });

  it("suggests allow commands for an unlisted destination and toolClasses for unknown tools", () => {
    const newDestination = explainEvent({ ...base, action: "block", matched_rule: { id: "block-new-destination" }, metadata: { destination: { hosts: ["api.example.com"], emailRecipients: [] } } });
    expect(newDestination.fixes).toContain("palizade allow host api.example.com");
    const unknown = explainEvent({ ...base, server: "crm", tool: "frob", action: "block", matched_rule: { id: "block-untrusted-unknown-tool" } });
    expect(unknown.fixes.join("\n")).toContain("servers.crm.toolClasses.frob");
  });

  it("falls back to the recorded reason and only picks decisions that stopped or paused a call", () => {
    expect(explainEvent({ ...base, action: "block", reason: "custom rule says no", matched_rule: { id: "my-rule" } }).summary).toBe("custom rule says no");
    expect(isInteresting({ ...base, action: "allow" })).toBe(false);
    expect(isInteresting({ ...base, action: "require_approval" })).toBe(true);
  });
});
