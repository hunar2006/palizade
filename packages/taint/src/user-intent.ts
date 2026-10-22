import { HIDDEN_UNICODE, canonicalEmail, canonicalHost } from "./unicode.js";

// Destinations a user typed themselves (in a prompt) are their intent, even when the same value
// also appears in untrusted content. Only destination shaped values count: urls, email addresses,
// host names, @handles, #channels, account or IBAN style identifiers and phone numbers. Ordinary
// words never do, so a prompt cannot vouch for copied prose.
const PATTERNS: Array<{ kind: string; regex: RegExp }> = [
  { kind: "url", regex: /\bhttps?:\/\/[^\s<>"'`)\]]+/giu },
  { kind: "email", regex: /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}(?![\p{L}\p{N}-])/giu },
  { kind: "host", regex: /(?<![\p{L}\p{N}@._/-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,}(?![\p{L}\p{N}@-]|\.[\p{L}\p{N}])/giu },
  { kind: "handle", regex: /(?<![\p{L}\p{N}._%+-])[@#][\p{L}\p{N}][\p{L}\p{N}._-]{1,63}(?![\p{L}\p{N}])/gu },
  // Two letters then digits and letters, 8 to 34 long (IBAN shape), or long digit runs (accounts, phones).
  { kind: "account", regex: /(?<![\p{L}\p{N}])(?:[A-Z]{2}\d{2}[A-Z0-9]{4,30}|\+?\d[\d -]{6,22}\d)(?![\p{L}\p{N}])/gu }
];

function clean(text: string): string {
  return text.normalize("NFKC").replace(HIDDEN_UNICODE, "");
}

/** Canonical forms of one matched span; a url also vouches for its host. */
function canonicalForms(kind: string, raw: string): string[] {
  const value = raw.replace(/[.,;:!?]+$/u, "");
  switch (kind) {
    case "url": {
      try {
        const url = new URL(value);
        url.hostname = canonicalHost(url.hostname);
        return [`url:${url.toString().toLowerCase()}`, `host:${canonicalHost(url.hostname)}`];
      } catch {
        return [];
      }
    }
    case "email":
      return [`email:${canonicalEmail(value)}`];
    case "host":
      return [`host:${canonicalHost(value)}`];
    case "handle":
      return [`handle:${value.toLowerCase()}`];
    default: {
      const compact = value.replace(/[\s-]/gu, "").toUpperCase();
      return compact.replace(/^\+/u, "").length >= 7 ? [`account:${compact.replace(/^\+/u, "")}`] : [];
    }
  }
}

interface Span { start: number; end: number; forms: string[] }

function spans(text: string): Span[] {
  const found: Span[] = [];
  for (const { kind, regex } of PATTERNS) {
    for (const match of text.matchAll(regex)) {
      const forms = canonicalForms(kind, match[0]);
      if (forms.length > 0) found.push({ start: match.index, end: match.index + match[0].length, forms });
    }
  }
  return found;
}

/** Canonical destination values stated in user written text, such as a prompt. */
export function extractStatedObservables(text: string): string[] {
  return [...new Set(spans(clean(text)).flatMap((span) => span.forms))];
}

/**
 * Blanks out destination values the user stated, so taint matching only sees the rest of the
 * text. A url is blanked only when the user stated that exact url: stating a host does not
 * vouch for a path or query built from untrusted content.
 */
export function maskStatedObservables(text: string, isStated: (canonical: string) => boolean): { text: string; masked: string[] } {
  const cleaned = clean(text);
  const masked: string[] = [];
  const hits = spans(cleaned).filter((span) => {
    const stated = span.forms[0] !== undefined && isStated(span.forms[0]);
    if (stated) masked.push(span.forms[0]!);
    return stated;
  });
  if (hits.length === 0) return { text, masked };
  let out = "";
  let cursor = 0;
  for (const span of hits.sort((a, b) => a.start - b.start)) {
    if (span.start < cursor) continue;
    out += `${cleaned.slice(cursor, span.start)} `;
    cursor = span.end;
  }
  out += cleaned.slice(cursor);
  return { text: out, masked: [...new Set(masked)] };
}
