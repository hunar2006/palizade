import { domainToASCII, domainToUnicode } from "node:url";

// Matching view only: every Unicode default ignorable code point (covers TAG characters, fillers, bidi controls).
export const HIDDEN_UNICODE = /[\p{Default_Ignorable_Code_Point}\u2800]/gu;

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
  // Let the WHATWG URL parser canonicalize host spellings (IPv4 forms, percent-encoding, IDNA) so
  // every caller compares the same form a client would actually connect to.
  try {
    const parsed = new URL(`http://${host}/`).hostname.replace(/\.$/u, "");
    if (parsed) return parsed;
  } catch {
    // Not a valid URL host; fall back to IDNA only.
  }
  return domainToASCII(host) || host;
}

/** Lowercases and strips invisible characters from the local part, canonicalizes the domain. */
export function canonicalEmail(input: string): string {
  const text = input.normalize("NFKC").replace(HIDDEN_UNICODE, "").trim().toLowerCase();
  const at = text.lastIndexOf("@");
  if (at <= 0 || at === text.length - 1) return text;
  return `${text.slice(0, at)}@${canonicalHost(text.slice(at + 1))}`;
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
