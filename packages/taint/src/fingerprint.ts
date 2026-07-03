import { sha256 } from "./hash.js";
import type { TaintFingerprint } from "./types.js";

const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
const BASE64_RE = /\b[A-Za-z0-9+/]{40,}={0,2}\b/gu;
const HEX_RE = /\b[a-fA-F0-9]{48,}\b/gu;

export function normalizeText(input: string): string {
  return input
    .normalize("NFKC")
    .replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u206F]/gu, "")
    .replace(/\s+/gu, " ")
    .trim()
    .toLowerCase();
}

export function extractAtomicTokens(input: string): string[] {
  const tokens = new Set<string>();
  for (const regex of [URL_RE, EMAIL_RE, BASE64_RE, HEX_RE]) {
    for (const match of input.matchAll(regex)) {
      tokens.add(match[0]);
    }
  }
  return [...tokens];
}

export function makeFingerprint(input: string): TaintFingerprint {
  const normalized = normalizeText(input);
  return {
    normalized,
    substrings: makeSubstrings(normalized),
    tokens: extractAtomicTokens(input),
    simhash: simhash(normalized)
  };
}

export function makeSubstrings(normalized: string, size = 48, stride = 24, max = 160): string[] {
  if (normalized.length < size) {
    return normalized.length >= 16 ? [normalized] : [];
  }
  const chunks: string[] = [];
  for (let index = 0; index <= normalized.length - size && chunks.length < max; index += stride) {
    chunks.push(normalized.slice(index, index + size));
  }
  return chunks;
}

export function simhash(normalized: string): string {
  const shingles = wordShingles(normalized);
  const vector = new Array<number>(64).fill(0);
  for (const shingle of shingles) {
    const hash = sha256(shingle).slice(0, 16);
    const bits = BigInt(`0x${hash}`);
    for (let bit = 0; bit < 64; bit += 1) {
      vector[bit]! += (bits & (1n << BigInt(bit))) === 0n ? -1 : 1;
    }
  }
  let result = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if ((vector[bit] ?? 0) >= 0) {
      result |= 1n << BigInt(bit);
    }
  }
  return result.toString(16).padStart(16, "0");
}

export function hammingDistanceHex(a: string, b: string): number {
  let left = BigInt(`0x${a}`);
  const right = BigInt(`0x${b}`);
  left ^= right;
  let count = 0;
  while (left > 0n) {
    count += Number(left & 1n);
    left >>= 1n;
  }
  return count;
}

function wordShingles(normalized: string): string[] {
  const words = normalized.match(/[\p{L}\p{N}_-]+/gu) ?? [];
  if (words.length === 0) {
    return [normalized.slice(0, 64)];
  }
  if (words.length < 4) {
    return [words.join(" ")];
  }
  const shingles: string[] = [];
  for (let index = 0; index <= words.length - 4; index += 1) {
    shingles.push(words.slice(index, index + 4).join(" "));
  }
  return shingles;
}
