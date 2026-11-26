import { hash } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { IANA_TLDS } from "./iana-tlds.js";
import type { TaintFingerprint } from "./types.js";
import { canonicalEmail, canonicalHost, HIDDEN_UNICODE, tokenViews } from "./unicode.js";

const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
// Starts only where a run of local part characters starts: with \b, a long "a.a.a..." run was
// retried from every letter, which took seconds on a few tens of KB.
const EMAIL_RE = /(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
const BASE64_RE = /\b[A-Za-z0-9+/]{40,}={0,2}\b/gu;
const HEX_RE = /\b[a-fA-F0-9]{48,}\b/gu;
const HOSTNAME = String.raw`(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+([\p{L}][\p{L}\p{M}]{1,23}|xn--[\da-z]{1,59})\.?`;
const BARE_HOST_RE = new RegExp(String.raw`(?<![\p{L}\p{N}@._/\\-])${HOSTNAME}(?![\p{L}\p{N}@_-]|\.[a-z0-9._-])`, "giu");
const SCP_HOST_RE = new RegExp(String.raw`(?<![\p{L}\p{N}@._/\\-])(?:[a-z0-9._-]+@)?(${HOSTNAME}):[/~\w.-][^\s<>"')]*`, "giu");
const IPV4_RE = /(?<![\p{L}\d._-])\d{1,3}(?:\.\d{1,3}){3}(?![\p{L}\d_-]|\.[\p{L}\d._-])/gu;
const IPV6_RE = /\[[0-9a-f:.]*:[0-9a-f:.]*\]/giu;
const BARE_IPV6_RE = /(?<![\da-f:.])([\da-f:.]*:[\da-f:.]*:[\da-f:.]*)(?![\da-f:.])/giu;
const SPECIAL_USE_TLDS = ["test", "example", "invalid", "internal", "onion"] as const;
const DESTINATION_TLDS = new Set([...IANA_TLDS, ...SPECIAL_USE_TLDS]);
// Common source, script, document, archive and media extensions that are also IANA TLDs.
const FILE_EXTENSION_TLDS = new Set(["sh", "py", "md", "zip", "rs", "pl", "ps", "so", "cc", "mov", "app", "tf", "mk", "ml", "pm", "java"]);
const SCHEME_HOST_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"')]+/giu;
const NETWORK_HOST_PREFIX = /\b(curl|wget|nc|ncat|ssh|ftp|sftp|ping|nslookup|dig|telnet|invoke-webrequest|invoke-restmethod|iwr|irm|test-netconnection|tnc|resolve-dnsname)((?:[ \t]+-[\w-]+)*?)[ \t]+(?:(?:--url|-uri|-computername|-name)(?:[ \t]+|[=:]))?["']?$/iu;
const SCP_STAGE_PREFIX = /\b(?:scp|rsync)[ \t]+[^;&|\r\n]*$/iu;

function isDestinationTld(tld: string): boolean {
  const lower = tld.toLowerCase();
  return DESTINATION_TLDS.has(domainToASCII(lower) || lower);
}

function isNetworkHostArgument(prefix: string): boolean {
  const match = NETWORK_HOST_PREFIX.exec(prefix);
  if (!match) return false;
  const verb = match[1]!.toLowerCase();
  const switches = verb === "curl" ? /^(?:-[fsSLkqvIOJ46]+|--silent|--verbose)$/u
    : verb === "wget" ? /^(?:-[qvNS46]+|--quiet|--verbose)$/u : /^-[qv46]+$/u;
  return (match[2]!.match(/\S+/gu) ?? []).every((flag) => switches.test(flag));
}

export function isMatchableToken(token: string): boolean {
  return (token.length >= 8 && token !== "req.body") || /^[\w.%+-]+@[\w.-]+\.[a-z]{2,}$/iu.test(token);
}

export function canonicalDestinationUrl(value: string): URL | null {
  const url = URL.parse(value.normalize("NFKC").replace(HIDDEN_UNICODE, ""));
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) return null;
  url.hostname = canonicalHost(url.hostname);
  return url;
}

export function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || (host.startsWith("127.") && isIP(host) === 4) || host === "0.0.0.0" ||
    host === "[::1]" || host === "[::]" || /^\[::ffff:7f[\da-f]{2}:[\da-f]+\]$/u.test(host);
}

export function trimMatchedUrl(raw: string): string {
  let out = raw.replace(/[.,;:!?]+$/u, "");
  while (out.endsWith("]") && (out.match(/\]/gu)?.length ?? 0) > (out.match(/\[/gu)?.length ?? 0)) {
    out = out.slice(0, -1).replace(/[.,;:!?]+$/u, "");
  }
  return out;
}

export function extractDestinationObservables(text: string, destinationOnly = false): string[] {
  const observables = new Set<string>();
  const addHost = (input: string) => {
    const host = canonicalHost(input);
    if (!host || isLoopbackHost(host)) return;
    observables.add(host);
    return host;
  };
  const view = text.normalize("NFKC").replace(HIDDEN_UNICODE, "");
  const remainder = view.replace(SCHEME_HOST_RE, (match) => {
    const url = URL.parse(trimMatchedUrl(match));
    if (url?.hostname) {
      const host = addHost(url.hostname);
      if (host && /^https?:$/u.test(url.protocol)) {
        url.hostname = host;
        observables.add(url.toString());
      }
    }
    return " ";
  }).replace(SCP_HOST_RE, (match: string, host: string, tld: string) => {
    if (!isDestinationTld(tld)) return match;
    addHost(host);
    return " ";
  }).replace(EMAIL_RE, (match) => {
    observables.add(canonicalEmail(match.replace(/^[.%+-]+/u, "")));
    return " ";
  });
  for (const match of remainder.matchAll(BARE_HOST_RE)) {
    const [host, tld] = match;
    if (!tld || !isDestinationTld(tld)) continue;
    if (destinationOnly && FILE_EXTENSION_TLDS.has(tld.toLowerCase()) && host.replace(/\.$/u, "").split(".").length === 2) {
      const next = remainder[match.index + host.length];
      const prefix = remainder.slice(Math.max(0, match.index - 256), match.index);
      if (next !== "/" && !(next === ":" && SCP_STAGE_PREFIX.test(prefix)) && !isNetworkHostArgument(prefix)) continue;
    }
    addHost(host);
  }
  for (const [literal] of remainder.matchAll(IPV4_RE)) {
    if (isIP(literal) === 4) addHost(literal);
  }
  const withoutBracketedIpv6 = remainder.replace(IPV6_RE, (literal) => {
    if (isIP(literal.slice(1, -1)) === 6) addHost(literal);
    return " ";
  });
  for (const [, literal] of withoutBracketedIpv6.matchAll(BARE_IPV6_RE)) {
    const candidate = literal?.replace(/\.+$/u, "");
    if (candidate && isIP(candidate) === 6) addHost(`[${candidate}]`);
  }
  if (isIP(view.trim()) === 6) addHost(`[${view.trim()}]`);
  return [...observables];
}

export function canonicalFieldDestinations(text: string): string[] {
  const observables = new Set(extractDestinationObservables(text));
  const trimmed = text.normalize("NFKC").replace(HIDDEN_UNICODE, "").trim();
  if (trimmed && !/\s/u.test(trimmed)) {
    const parsedUrl = canonicalDestinationUrl(trimmed);
    const bare = trimmed.startsWith("[")
      ? trimmed.replace(/:\d+$/u, "")
      : (trimmed.match(/:/gu)?.length ?? 0) === 1
        ? trimmed.replace(/:\d+$/u, "")
        : trimmed;
    const withoutTrailingDot = bare.replace(/\.$/u, "");
    const decimalInt = /^\d+$/u.test(withoutTrailingDot);
    const intVal = decimalInt ? Number(withoutTrailingDot) : -1;
    const validDecimalIp = !decimalInt || (intVal >= 0x01000000 && intVal <= 0xffffffff);
    const candidate = parsedUrl ? parsedUrl.hostname : validDecimalIp ? canonicalHost(withoutTrailingDot) : "";
    if (candidate && !isLoopbackHost(candidate) && (parsedUrl || isIP(candidate.replace(/^\[|\]$/gu, "")) !== 0 || candidate.includes("."))) {
      observables.add(candidate);
      if (parsedUrl) observables.add(parsedUrl.toString());
    }
  }
  return [...observables];
}

export function normalizeText(input: string): string {
  return input
    .normalize("NFKC")
    .replace(HIDDEN_UNICODE, "")
    .replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u206F]/gu, "")
    .replace(/\s+/gu, " ")
    .trim()
    .toLowerCase();
}

export function extractAtomicTokens(input: string): string[] {
  const tokens = new Set<string>();
  for (const regex of [URL_RE, EMAIL_RE, BASE64_RE, HEX_RE, /(?<![\p{L}\p{N}@._-])[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)+/gu, /\b[A-Z][A-Z0-9_-]*\d[A-Z0-9_-]*\b/gu]) {
    for (const match of input.normalize("NFKC").replace(HIDDEN_UNICODE, "").matchAll(regex)) {
      // Leading punctuation was never part of an email match under \b; keep tokens the same.
      for (const token of tokenViews(regex === EMAIL_RE ? match[0].replace(/^[.%+-]+/u, "") : match[0])) tokens.add(token);
    }
  }
  return [...tokens];
}

export function isSubstringsTruncated(normalized: string, k = 32, w = 16, max = 2048): boolean {
  const covered = max * Math.ceil((w + 1) / 2);
  return normalized.length >= k && normalized.length > covered + k;
}

export function makeFingerprint(input: string, sensitive = false, destinationOnly = false): TaintFingerprint {
  if (destinationOnly) {
    return { normalized: "", fragmentLength: 0, substrings: [], tokens: [], simhash: "", destinationTokens: extractDestinationObservables(input, true) };
  }
  const normalized = normalizeText(input);
  return {
    normalized,
    substrings: makeSubstrings(normalized),
    tokens: extractAtomicTokens(input).map(normalizeText).filter(isMatchableToken),
    simhash: simhash(normalized),
    ...(sensitive ? { sensitiveFragments: makeSensitiveFragments(normalized) } : {}),
    ...(isSubstringsTruncated(normalized) ? { truncated: true } : {})
  };
}

// shortcut: sensitive shard coverage is bounded to 2048 eight-character fragments, raise the bound for larger sensitive outputs.
export function makeSensitiveFragments(text: string): string[] {
  const fragments: string[] = [];
  for (let index = 0; index + 8 <= text.length && index < 2048; index++) fragments.push(text.slice(index, index + 8));
  return [...new Set(fragments)];
}

// Winnowing (Schleimer et al. 2003): keep the min-hash k-gram in every window of w k-grams.
// Selection depends only on content, so copied text matches at any offset; any shared run of
// at least k + w - 1 (47) chars is guaranteed to share a fragment. Fixed-stride windows were not.
// shortcut: stops after `max` fragments (~17 KB of text); injections past that rely on token,
// fuzzy and temporal matching. Raise max or switch to sampled coverage if long pages matter.
export function makeSubstrings(normalized: string, k = 32, w = 16, max = 2048): string[] {
  if (normalized.length < k) {
    return normalized.length >= 16 ? [normalized] : [];
  }
  // Winnowing picks about one k-gram per (w + 1) / 2 characters, so `max` picks cover this much text.
  const covered = max * Math.ceil((w + 1) / 2);
  if (normalized.length > covered + k) {
    // Long pages: split the same budget between the start and the end, where injected text usually sits.
    const half = Math.floor(covered / 2) + k - 1;
    const head = winnow(normalized.slice(0, half), k, w, Math.floor(max / 2));
    // Keep the last picks of the tail slice, so the final characters are always covered.
    const tail = winnow(normalized.slice(-half), k, w, half).slice(-Math.floor(max / 2));
    return [...new Set([...head, ...tail])];
  }
  return winnow(normalized, k, w, max);
}

function winnow(normalized: string, k: number, w: number, max: number): string[] {
  // At most one new pick per window, so max * w k-grams always suffices; bounds work on huge pages.
  const grams = Math.min(normalized.length - k + 1, max * w);
  const hashes = new Array<number>(grams);
  for (let index = 0; index < grams; index += 1) {
    hashes[index] = fnv1a(normalized, index, index + k);
  }
  const picked: number[] = [];
  for (let start = 0; start + Math.min(w, grams) <= grams && picked.length < max; start += 1) {
    let best = start;
    for (let index = start + 1; index < Math.min(start + w, grams); index += 1) {
      // Rightmost minimum, so ties pick the same k-gram across overlapping windows.
      if (hashes[index]! <= hashes[best]!) best = index;
    }
    if (picked.at(-1) !== best) picked.push(best);
  }
  return [...new Set(picked.map((index) => normalized.slice(index, index + k)))];
}

function fnv1a(text: string, from: number, to: number): number {
  let hash = 0x811c9dc5;
  for (let index = from; index < to; index += 1) {
    hash = Math.imul(hash ^ text.charCodeAt(index), 0x01000193);
  }
  return hash >>> 0;
}

export function simhash(normalized: string): string {
  const shingles = wordShingles(normalized);
  const vector = new Int32Array(64);
  for (const shingle of shingles) {
    // The top 64 bits of SHA-256, read big endian: bit i lives in byte 7 - (i >> 3).
    const digest = hash("sha256", shingle, "buffer");
    for (let bit = 0; bit < 64; bit += 1) {
      vector[bit]! += (digest[7 - (bit >> 3)]! >> (bit & 7)) & 1 ? 1 : -1;
    }
  }
  const out = Buffer.alloc(8);
  for (let bit = 0; bit < 64; bit += 1) {
    if (vector[bit]! >= 0) out[7 - (bit >> 3)] = out[7 - (bit >> 3)]! | (1 << (bit & 7));
  }
  // Same hex as before (BigInt.toString(16) padded to 16), so stored fingerprints stay comparable.
  return out.toString("hex");
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
