import { domainToUnicode } from "node:url";

export interface DecodeLimits { maxDepth: number; maxBytes: number }
export interface MatchCandidate { text: string; kind: string }
const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", colon: ":", sol: "/", commat: "@", period: ".", equals: "=" };

function printable(bytes: Buffer): string | undefined {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const chars = [...text];
    return chars.length && chars.filter((char) => !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(char)).length / chars.length >= 0.9 ? text : undefined;
  } catch { return undefined; }
}

export function expandCandidates(text: string, limits: DecodeLimits = { maxDepth: 2, maxBytes: 256 * 1024 }): MatchCandidate[] {
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 0 || !Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 1) throw new Error("Invalid decode limits");
  const candidates: MatchCandidate[] = [{ text, kind: "original" }];
  const seen = new Set([text]);
  let bytes = 0;
  let frontier = candidates;
  for (let depth = 0; depth < limits.maxDepth; depth++) {
    const next: MatchCandidate[] = [];
    for (const parent of frontier) {
      const add = (value: string, kind: string) => {
        if (!value || seen.has(value)) return;
        bytes += Buffer.byteLength(value);
        if (bytes > limits.maxBytes) throw new Error("Decoded candidate byte limit exceeded");
        seen.add(value);
        next.push({ text: value, kind: parent.kind === "original" ? kind : `${parent.kind}+${kind}` });
      };
      const replace = (regex: RegExp, kind: string, decode: (value: string) => string | undefined) => {
        const result = parent.text.replace(regex, (value) => {
          const decoded = decode(value);
          if (decoded !== undefined && decoded !== value) { add(decoded, kind); return decoded; }
          return value;
        });
        if (result !== parent.text) add(result, kind);
      };
      replace(/=\?utf-8\?[bq]\?[^?]*\?=/giu, "rfc2047", (value) => {
        const parts = /^=\?utf-8\?([bq])\?([^?]*)\?=$/iu.exec(value)!;
        return parts[1]!.toLowerCase() === "b" ? printable(Buffer.from(parts[2]!, "base64")) : printable(Buffer.from(parts[2]!.replace(/_/gu, " ").replace(/=([\da-f]{2})/giu, (_match, hex: string) => String.fromCharCode(parseInt(hex, 16))), "latin1"));
      });
      replace(/(?<![\w+/-])[A-Za-z0-9+/_-]{16,}={0,2}(?![\w+/-])/gu, "base64", (value) => printable(Buffer.from(value, "base64url")));
      replace(/(?<![\da-f])[\da-f]{32,}(?![\da-f])/giu, "hex", (value) => value.length % 2 === 0 ? printable(Buffer.from(value, "hex")) : undefined);
      replace(/(?:%[\da-f]{2})+/giu, "percent", (value) => printable(Buffer.from(value.replace(/%/gu, ""), "hex")));
      // shortcut: common named HTML entities only, extend the table when uncommon named entities appear in attacks.
      replace(/&(?:#x[\da-f]+|#\d+|[a-z]+);/giu, "html", (value) => {
        const entity = value.slice(1, -1).toLowerCase();
        if (!entity.startsWith("#")) return ENTITIES[entity];
        const point = entity.startsWith("#x") ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
        return point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : undefined;
      });
      replace(/\\(?:u[\da-f]{4}|x[\da-f]{2}|n|r|t|\\|"|\/)/giu, "escape", (value) => {
        if (value[1] === "u" || value[1] === "x") return String.fromCharCode(parseInt(value.slice(2), 16));
        return ({ n: "\n", r: "\r", t: "\t" } as Record<string, string>)[value[1]!] ?? value.slice(1);
      });
      replace(/(?:xn--[a-z0-9-]+)(?:\.[a-z0-9-]+)*/giu, "punycode", (value) => domainToUnicode(value) || undefined);
    }
    candidates.push(...next);
    frontier = next;
    if (!next.length) break;
  }
  return candidates;
}
