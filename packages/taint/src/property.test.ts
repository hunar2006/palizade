import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { expandCandidates } from "./decode.js";
import { extractAtomicTokens, makeFingerprint, normalizeText } from "./fingerprint.js";
import { HIDDEN_UNICODE } from "./unicode.js";
import { extractStatedObservables, maskStatedObservables } from "./user-intent.js";

// Characters that exercise the decoders, encodings and destination patterns.
const pieces = ["a", "Z", "9", ".", "-", "_", "@", "#", "%", "+", "=", "&", ";", "\\", "/", ":", " ", "\n", "\t", "x", "n", "u", "?",
  "%41", "&amp;", "&#x41;", "\\u0041", "\\x41", "=?utf-8?b?", "?=", "xn--", "http://", "https://a.example/", "QUJDREVGR0hJSktMTU5PUA",
  "é", "😀", "​", "‮", "\u0000", "️", "ｈ"];
const text = (maxLength = 60) => fc.array(fc.constantFrom(...pieces), { maxLength }).map((parts) => parts.join(""));
const anyText = fc.oneof(text(), fc.string({ unit: "binary", maxLength: 200 }));
const within = (ms: number, run: () => unknown) => {
  const start = performance.now();
  run();
  return performance.now() - start < ms;
};

describe("normalizeText", () => {
  it("is idempotent and leaves no hidden or control characters, case or edge spaces", () => {
    fc.assert(fc.property(anyText, (input) => {
      const once = normalizeText(input);
      expect(normalizeText(once)).toBe(once);
      expect(once).toBe(once.trim());
      expect(once).toBe(once.toLowerCase());
      expect(/[\u0000-\u001F\u007F​-‏‪-‮⁠-⁯]/u.test(once)).toBe(false);
      expect(new RegExp(HIDDEN_UNICODE.source, HIDDEN_UNICODE.flags.replace("g", "")).test(once)).toBe(false);
      expect(once.includes("  ")).toBe(false);
    }));
  });
});

describe("expandCandidates", () => {
  it("keeps the original first, adds no duplicates, and stays within its byte limit or throws that limit", () => {
    fc.assert(fc.property(anyText, fc.integer({ min: 0, max: 3 }), fc.integer({ min: 1, max: 4096 }), (input, maxDepth, maxBytes) => {
      let candidates;
      try { candidates = expandCandidates(input, { maxDepth, maxBytes }); }
      catch (error) { expect((error as Error).message).toBe("Decoded candidate byte limit exceeded"); return; }
      expect(candidates[0]).toEqual({ text: input, kind: "original" });
      expect(new Set(candidates.map((candidate) => candidate.text)).size).toBe(candidates.length);
      const added = candidates.slice(1).reduce((sum, candidate) => sum + Buffer.byteLength(candidate.text), 0);
      expect(added).toBeLessThanOrEqual(maxBytes);
    }));
  });

  it("rejects invalid limits instead of looping", () => {
    for (const limits of [{ maxDepth: -1, maxBytes: 1 }, { maxDepth: 1, maxBytes: 0 }, { maxDepth: Number.POSITIVE_INFINITY, maxBytes: 1 }, { maxDepth: 1, maxBytes: Number.NaN }]) {
      expect(() => expandCandidates("x", limits)).toThrow("Invalid decode limits");
    }
  });
});

describe("user intent masking", () => {
  it("never throws, masks nothing unless asked, and only replaces stated values", () => {
    fc.assert(fc.property(anyText, (input) => {
      const stated = extractStatedObservables(input);
      expect(maskStatedObservables(input, () => false)).toEqual({ text: input, masked: [] });
      const all = maskStatedObservables(input, () => true);
      for (const value of all.masked) expect(stated).toContain(value);
      // Masked text holds no destination that was stated.
      for (const value of extractStatedObservables(all.text)) expect(all.masked).not.toContain(value);
    }));
  });
});

// Old fingerprint email pattern, kept as an oracle: the new one must find the same tokens.
const OLD_EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
describe("fingerprint tokens", () => {
  it("finds the same email tokens as the old pattern", () => {
    const emailish = fc.array(fc.constantFrom("a", "b", "1", "_", ".", "-", "%", "+", "@", "x.com", " ", "(", "é"), { maxLength: 40 }).map((parts) => parts.join(""));
    fc.assert(fc.property(emailish, (input) => {
      const old = new Set([...input.normalize("NFKC").matchAll(OLD_EMAIL)].map((match) => match[0]));
      const tokens = new Set(extractAtomicTokens(input));
      for (const email of old) expect(tokens.has(email)).toBe(true);
    }));
  });
});

describe("regressions: linear time on long inputs (1 MB is the default hook input limit)", () => {
  const long = (unit: string) => unit.repeat(Math.ceil(1024 * 1024 / unit.length));
  it("fingerprints a long dotted run quickly (was seconds at 32 KB)", () => {
    expect(within(5000, () => makeFingerprint(long("a.")))).toBe(true);
    expect(within(5000, () => makeFingerprint(`a@${long("a.")}`))).toBe(true);
  });
  it("extracts destinations from long adversarial prompts quickly", () => {
    for (const unit of ["a.", "a-", "a@", "1 ", "@a"]) expect(within(5000, () => extractStatedObservables(long(unit)))).toBe(true);
  });
});
