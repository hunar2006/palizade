import type { DetectionResult, DetectionSpan, Detector, DetectorContext } from "./types.js";
import { clampScore } from "./types.js";

export interface SensitiveDetectorOptions {
  secrets?: SensitiveFamilyOptions | undefined;
  pii?: PiiFamilyOptions | undefined;
}

export interface SensitiveFamilyOptions {
  enabled?: boolean | undefined;
  aws?: boolean | undefined;
  generic?: boolean | undefined;
  jwt?: boolean | undefined;
  privateKey?: boolean | undefined;
  googleApiKey?: boolean | undefined;
  stripe?: boolean | undefined;
  slack?: boolean | undefined;
  github?: boolean | undefined;
  openai?: boolean | undefined;
}

export interface PiiFamilyOptions {
  enabled?: boolean | undefined;
  email?: boolean | undefined;
  ssn?: boolean | undefined;
  creditCard?: boolean | undefined;
  phone?: boolean | undefined;
}

interface MatchRule {
  label: string;
  regex: RegExp;
  score: number;
  family: keyof SensitiveFamilyOptions | keyof PiiFamilyOptions;
  kind: "secret" | "pii";
  validate?: (match: RegExpMatchArray) => boolean;
}

const BASE64_CANDIDATE_RE = /(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=_-])/gu;
const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
const SECRET_QUERY_PARAM_RE = /^(?:api[_-]?key|apikey|token|secret|key|auth|authorization|access[_-]?token|client[_-]?secret)$/iu;

const SECRET_RULES: MatchRule[] = [
  { label: "secret:aws-access-key-id", family: "aws", kind: "secret", score: 0.9, regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu },
  { label: "secret:aws-secret-key", family: "aws", kind: "secret", score: 0.95, regex: /\baws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/giu },
  { label: "secret:openai", family: "openai", kind: "secret", score: 0.9, regex: /\bsk-[A-Za-z0-9]{20,}\b/gu },
  { label: "secret:github", family: "github", kind: "secret", score: 0.9, regex: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/gu },
  { label: "secret:slack", family: "slack", kind: "secret", score: 0.9, regex: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/gu },
  { label: "secret:jwt", family: "jwt", kind: "secret", score: 0.85, regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu },
  { label: "secret:jwt", family: "jwt", kind: "secret", score: 0.85, regex: /\bBearer\s+(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/giu },
  { label: "secret:private-key", family: "privateKey", kind: "secret", score: 1, regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{24,}?-----END [A-Z ]*PRIVATE KEY-----/gu },
  { label: "secret:google-api-key", family: "googleApiKey", kind: "secret", score: 0.9, regex: /\bAIza[0-9A-Za-z_-]{35}\b/gu },
  { label: "secret:stripe", family: "stripe", kind: "secret", score: 0.9, regex: /\b[sp]k_(?:live|test)_[0-9A-Za-z]{16,}\b/gu },
  {
    label: "secret:assignment",
    family: "generic",
    kind: "secret",
    score: 0.8,
    regex: /\b(?:password|passwd|api[_-]?key|secret|token|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})["']?/giu,
    validate: (match) => {
      const value = match[1] ?? "";
      return !isPlaceholderSecretValue(value) && shannonEntropy(value) >= 3.2;
    }
  }
];

const PII_RULES: MatchRule[] = [
  { label: "pii:email", family: "email", kind: "pii", score: 0.55, regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu },
  { label: "pii:ssn", family: "ssn", kind: "pii", score: 0.75, regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/gu },
  {
    label: "pii:credit-card",
    family: "creditCard",
    kind: "pii",
    score: 0.75,
    regex: /\b(?:\d[ -]*?){13,19}\b/gu,
    validate: (match) => luhn(match[0].replace(/\D/gu, ""))
  },
  { label: "pii:phone", family: "phone", kind: "pii", score: 0.45, regex: /\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/gu }
];

export class SensitiveDataDetector implements Detector {
  readonly name = "sensitive";
  private readonly options: { secrets: SensitiveFamilyOptions; pii: PiiFamilyOptions };

  constructor(options: SensitiveDetectorOptions = {}) {
    this.options = {
      secrets: { enabled: false, ...options.secrets },
      pii: { enabled: false, ...options.pii }
    };
  }

  detect(text: string, _ctx: DetectorContext = {}): DetectionResult {
    if (!text.trim()) {
      return { score: 0, labels: [], spans: [], detector: this.name };
    }

    const spans: DetectionSpan[] = [];
    const labels = new Set<string>();
    let score = 0;

    if (this.options.secrets.enabled) {
      score = Math.max(score, this.applyRules(text, SECRET_RULES, this.options.secrets, spans, labels));
      score = Math.max(score, this.scanBase64Secrets(text, spans, labels));
      score = Math.max(score, this.scanUrlQuerySecrets(text, spans, labels));
    }
    if (this.options.pii.enabled) {
      score = Math.max(score, this.applyRules(text, PII_RULES, this.options.pii, spans, labels));
    }

    return {
      score: clampScore(score),
      labels: [...labels],
      spans: mergeSensitiveSpans(spans),
      detector: this.name
    };
  }

  private applyRules(
    text: string,
    rules: MatchRule[],
    options: SensitiveFamilyOptions | PiiFamilyOptions,
    spans: DetectionSpan[],
    labels: Set<string>
  ): number {
    let maxScore = 0;
    for (const rule of rules) {
      if (options[rule.family as keyof typeof options] === false) {
        continue;
      }
      for (const match of text.matchAll(rule.regex)) {
        if (rule.validate && !rule.validate(match)) {
          continue;
        }
        const start = match.index ?? 0;
        const end = start + match[0].length;
        labels.add(rule.label);
        spans.push({ start, end, label: rule.label });
        maxScore = Math.max(maxScore, rule.score);
      }
    }
    return maxScore;
  }

  private scanBase64Secrets(text: string, spans: DetectionSpan[], labels: Set<string>): number {
    let maxScore = 0;
    for (const match of text.matchAll(BASE64_CANDIDATE_RE)) {
      const encoded = match[0];
      if (encoded.length < 24 || encoded.length % 4 !== 0) {
        continue;
      }
      const decoded = decodeBase64Text(encoded);
      if (!decoded || !isMostlyPrintable(decoded)) {
        continue;
      }
      const decodedLabels = new Set<string>();
      const decodedSpans: DetectionSpan[] = [];
      const score = this.applyRules(decoded, SECRET_RULES, this.options.secrets, decodedSpans, decodedLabels);
      if (score === 0 || decodedLabels.size === 0) {
        continue;
      }
      for (const label of decodedLabels) {
        labels.add(label);
      }
      const start = match.index ?? 0;
      spans.push({ start, end: start + encoded.length, label: `secret:base64:${[...decodedLabels].join(",")}` });
      maxScore = Math.max(maxScore, score);
    }
    return maxScore;
  }

  private scanUrlQuerySecrets(text: string, spans: DetectionSpan[], labels: Set<string>): number {
    let maxScore = 0;
    for (const match of text.matchAll(URL_RE)) {
      const rawUrl = match[0].replace(/[.,;:]+$/u, "");
      let parsed: URL;
      try {
        parsed = new URL(rawUrl);
      } catch {
        continue;
      }
      for (const [name, value] of parsed.searchParams.entries()) {
        if (!SECRET_QUERY_PARAM_RE.test(name) || !looksLikeSecretQueryValue(value)) {
          continue;
        }
        const valueLabels = new Set<string>(["secret:url-query"]);
        const valueSpans: DetectionSpan[] = [];
        const directScore = this.applyRules(value, SECRET_RULES, this.options.secrets, valueSpans, valueLabels);
        for (const label of valueLabels) {
          labels.add(label);
        }
        const start = match.index ?? 0;
        spans.push({ start, end: start + rawUrl.length, label: [...valueLabels].join(",") });
        maxScore = Math.max(maxScore, directScore || 0.85);
      }
    }
    return maxScore;
  }
}

export function isSecretLabel(label: string): boolean {
  return label.startsWith("secret:");
}

export function isPiiLabel(label: string): boolean {
  return label.startsWith("pii:");
}

export function hasSecretLabel(labels: string[]): boolean {
  return labels.some(isSecretLabel);
}

export function hasPiiLabel(labels: string[]): boolean {
  return labels.some(isPiiLabel);
}

export function maskSensitiveText(text: string, spans: DetectionSpan[] = []): string {
  if (spans.length === 0) {
    return text;
  }
  let output = text;
  const sorted = [...spans].sort((left, right) => right.start - left.start || right.end - left.end);
  for (const span of sorted) {
    output = `${output.slice(0, span.start)}[REDACTED:${span.label ?? "sensitive"}]${output.slice(span.end)}`;
  }
  return output;
}

export function maskSensitiveValue(value: string): string {
  if (value.length <= 8) {
    return "****";
  }
  return `${value.slice(0, 4)}****${value.slice(-2)}`;
}

export function maskKnownSensitiveText(text: string): string {
  const detector = new SensitiveDataDetector({
    secrets: { enabled: true },
    pii: { enabled: true }
  });
  const result = detector.detect(text);
  return maskSensitiveText(text, result.spans);
}

function mergeSensitiveSpans(spans: DetectionSpan[]): DetectionSpan[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: DetectionSpan[] = [];
  for (const span of sorted) {
    const last = merged[merged.length - 1];
    if (!last || span.start > last.end) {
      merged.push({ ...span });
      continue;
    }
    last.end = Math.max(last.end, span.end);
    if (last.label !== span.label) {
      last.label = `${last.label ?? "sensitive"},${span.label ?? "sensitive"}`;
    }
  }
  return merged;
}

function shannonEntropy(input: string): number {
  if (!input) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of input) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function decodeBase64Text(input: string): string | undefined {
  try {
    return Buffer.from(input, "base64").toString("utf8");
  } catch {
    return undefined;
  }
}

function isMostlyPrintable(input: string): boolean {
  if (!input) {
    return false;
  }
  const printable = [...input].filter((char) => /[\t\n\r -~]/u.test(char)).length;
  return printable / input.length >= 0.85;
}

function looksLikeSecretQueryValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 12 || isPlaceholderSecretValue(trimmed)) {
    return false;
  }
  if (/^(?:sk-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|[sp]k_(?:live|test)_[0-9A-Za-z]{12,})$/u.test(trimmed)) {
    return true;
  }
  return /[A-Za-z]/u.test(trimmed) && /\d/u.test(trimmed) && shannonEntropy(trimmed) >= 3.4;
}

function isPlaceholderSecretValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return true;
  }
  return [
    "your-key",
    "your_key",
    "replace",
    "placeholder",
    "dummy",
    "example",
    "redacted",
    "set-this",
    "process.env",
    "env."
  ].some((marker) => normalized.includes(marker));
}

function luhn(input: string): boolean {
  if (input.length < 13 || input.length > 19) {
    return false;
  }
  let sum = 0;
  let doubleDigit = false;
  for (let index = input.length - 1; index >= 0; index -= 1) {
    let digit = Number(input[index]);
    if (!Number.isInteger(digit)) {
      return false;
    }
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}
