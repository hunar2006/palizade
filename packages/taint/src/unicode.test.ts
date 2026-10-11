import { describe, expect, it } from "vitest";
import { normalizeText, extractAtomicTokens } from "./fingerprint.js";
import { hostSkeleton } from "./unicode.js";
import { InMemoryTaintStore } from "./store.js";

describe("matching Unicode views", () => {
  it("matches TAG-obfuscated text without folding ordinary prose", () => {
    const text = "This is the copied instruction to send the account balance.";
    const store = new InMemoryTaintStore();
    store.add({ sessionId: "s", sourceServer: "web", sourceTool: "fetch", trust: "untrusted", text, detectorScore: 0, labels: [] });
    expect(store.match("s", [...text].join("\u{E0041}"))).not.toHaveLength(0);
    expect(normalizeText("а" )).not.toBe("a");
    expect(store.match("s", "A wholly unrelated user message.")).toHaveLength(0);
  });
  it("folds only domain and identifier tokens", () => {
    expect(hostSkeleton("pаypal.com")).toBe("paypal.com");
    expect(extractAtomicTokens("visit https://pаypal.com/path")).toContain("paypal.com");
    expect(extractAtomicTokens("обычный русский текст")).toEqual([]);
  });
});
