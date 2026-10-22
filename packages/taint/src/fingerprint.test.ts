import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { simhash } from "./fingerprint.js";

describe("simhash compatibility", () => {
  // The previous BigInt implementation, kept here so stored fingerprints stay comparable.
  function referenceSimhash(normalized: string): string {
    const words = normalized.match(/[\p{L}\p{N}_-]+/gu) ?? [];
    const shingles = words.length === 0 ? [normalized.slice(0, 64)] : words.length < 4 ? [words.join(" ")] : words.slice(0, words.length - 3).map((_, index) => words.slice(index, index + 4).join(" "));
    const vector = new Array<number>(64).fill(0);
    for (const shingle of shingles) {
      const bits = BigInt(`0x${createHash("sha256").update(shingle).digest("hex").slice(0, 16)}`);
      for (let bit = 0; bit < 64; bit += 1) vector[bit]! += (bits & (1n << BigInt(bit))) === 0n ? -1 : 1;
    }
    let result = 0n;
    for (let bit = 0; bit < 64; bit += 1) if ((vector[bit] ?? 0) >= 0) result |= 1n << BigInt(bit);
    return result.toString(16).padStart(16, "0");
  }

  it("matches the reference output", () => {
    const samples = ["", "a", "one two three", "the quick brown fox jumps over the lazy dog", "émoji 😀 text with ünïcode and numbers 42 99", "x".repeat(500), ...Array.from({ length: 50 }, (_, index) => `sample ${index} ${"lorem ipsum dolor sit amet ".repeat(index % 7)} end ${index * 31}`)];
    for (const sample of samples) expect(simhash(sample), sample).toBe(referenceSimhash(sample));
  });
});
