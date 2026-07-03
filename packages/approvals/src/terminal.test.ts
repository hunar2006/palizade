import { describe, expect, it } from "vitest";
import { StaticApprovalProvider, createApprovalRequest } from "./terminal.js";

describe("StaticApprovalProvider", () => {
  it("returns deterministic decisions for tests", async () => {
    const provider = new StaticApprovalProvider(false, "blocked in test");
    const decision = await provider.requestApproval(createApprovalRequest({
      sessionId: "s1",
      reason: "tainted sink",
      taintIds: ["t1"],
      summary: "send_email wants tainted URL",
      timeoutMs: 100
    }));

    expect(decision.approved).toBe(false);
    expect(decision.reason).toBe("blocked in test");
  });
});
