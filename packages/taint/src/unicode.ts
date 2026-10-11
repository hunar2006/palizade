import { domainToASCII, domainToUnicode } from "node:url";

export const HIDDEN_UNICODE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

// shortcut: compact common Latin lookalikes only, use the full UTS 39 table for broader identifier coverage.
const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i", ј: "j", к: "k", м: "m", т: "t", в: "b", н: "h", ѕ: "s",
  α: "a", ο: "o", ρ: "p", χ: "x", ν: "v", κ: "k", τ: "t", ι: "i", ε: "e", υ: "u", ϲ: "c"
};

export function identifierSkeleton(input: string): string {
  return [...input.normalize("NFKC").replace(HIDDEN_UNICODE, "").toLowerCase()]
    .map((char) => CONFUSABLES[char] ?? char).join("");
}

export function canonicalHost(input: string): string {
  const host = input.normalize("NFKC").replace(HIDDEN_UNICODE, "").trim().replace(/\.$/u, "").toLowerCase();
  return domainToASCII(host) || host;
}

export function hostSkeleton(input: string): string {
  return identifierSkeleton(domainToUnicode(canonicalHost(input)) || input);
}

export function tokenViews(token: string): string[] {
  try {
    const url = new URL(token);
    const host = canonicalHost(url.hostname);
    url.hostname = hostSkeleton(host);
    return [token, host, hostSkeleton(host), url.toString()];
  } catch {
    return [token, identifierSkeleton(domainToUnicode(token) || token)];
  }
}
