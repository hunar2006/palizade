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

describe("matching view strips all default ignorables", () => {
  it("matches text with fillers inserted between letters", () => {
    const filler = String.fromCodePoint(0x3164);
    expect(normalizeText([..."quarterly payroll export"].join(filler))).toBe("quarterly payroll export");
  });
});

describe("canonical destinations", () => {
  it("gives equivalent host spellings one form", async () => {
    const { canonicalHost, canonicalEmail } = await import("./unicode.js");
    expect(canonicalHost("EXAMPLE.com.")).toBe("example.com");
    expect(canonicalHost("127.1")).toBe("127.0.0.1");
    expect(canonicalHost("bücher.example")).toBe("xn--bcher-kva.example");
    expect(canonicalEmail("Ops@Example.COM.")).toBe("ops@example.com");
  });
});
