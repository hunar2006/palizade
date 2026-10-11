export interface HiddenUnicodeFinding {
  count: number;
  codePoints: string[];
}

export interface DangerousDefaultFinding {
  path: string;
  value: string;
}

const MAX_REPORTED_CODE_POINTS = 32;

const DEFAULT_DANGEROUS_PATTERNS = [
  "--no-sandbox",
  "--dangerously-skip-permissions",
  "--dangerously-bypass-approvals-and-sandbox",
  "--yolo",
  "--disable-web-security",
  "--allow-all",
  "autoApprove",
  "auto_approve",
  "bypassPermissions"
];

const DANGEROUS_BOOLEAN_KEYS = /^(auto_?approve|yolo|dangerously_?skip_?permissions|skip_?permissions|bypass_?permissions|no_?sandbox|disable_?sandbox)$/iu;

const TAG_START = 0xe0000;
const TAG_END = 0xe007f;
const BLACK_FLAG = 0x1f3f4;
const CANCEL_TAG = 0xe007f;

export function isHiddenCodePoint(cp: number): boolean {
  return (cp >= TAG_START && cp <= TAG_END) ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef) ||
    cp === 0x00ad ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0xfeff ||
    cp === 0x180e;
}

/**
 * Returns the indexes (in code points) of hidden characters that are not part of a valid emoji
 * sequence: TAG runs inside a subdivision flag and variation selectors after a pictograph are kept.
 */
function hiddenIndexes(cps: number[]): number[] {
  const hidden: number[] = [];
  for (let index = 0; index < cps.length; index += 1) {
    const cp = cps[index]!;
    if (cp === BLACK_FLAG) {
      let end = index + 1;
      while (end < cps.length && cps[end]! >= TAG_START && cps[end]! < CANCEL_TAG) end += 1;
      if (end > index + 1 && cps[end] === CANCEL_TAG) {
        index = end;
        continue;
      }
    }
    if (!isHiddenCodePoint(cp)) continue;
    const previous = index > 0 ? cps[index - 1]! : undefined;
    if ((cp === 0xfe0f || cp === 0xfe0e) && previous !== undefined && isEmojiBase(previous)) continue;
    if (cp === 0x200d && previous !== undefined && isEmojiBase(previous) && index + 1 < cps.length && isEmojiBase(cps[index + 1]!)) continue;
    hidden.push(index);
  }
  return hidden;
}

function isEmojiBase(cp: number): boolean {
  const char = String.fromCodePoint(cp);
  return /\p{Extended_Pictographic}|\p{Emoji_Modifier}|[0-9#*]/u.test(char) || cp === 0xfe0f;
}

export function findHiddenUnicode(text: string): HiddenUnicodeFinding {
  const cps = [...text].map((char) => char.codePointAt(0)!);
  const indexes = hiddenIndexes(cps);
  const codePoints = [...new Set(indexes.map((index) => formatCodePoint(cps[index]!)))].slice(0, MAX_REPORTED_CODE_POINTS);
  return { count: indexes.length, codePoints };
}

export function stripHiddenUnicode(text: string): string {
  const chars = [...text];
  const cps = chars.map((char) => char.codePointAt(0)!);
  const drop = new Set(hiddenIndexes(cps));
  if (drop.size === 0) return text;
  return chars.filter((_, index) => !drop.has(index)).join("");
}

export function formatCodePoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

/** Escapes every non printing character as \u{XXXX} so payloads can never be displayed invisibly. */
export function escapeNonPrinting(text: string): string {
  let output = "";
  for (const char of text) {
    const cp = char.codePointAt(0)!;
    if (char === "\\") {
      output += "\\\\";
    } else if (char === "\n") {
      output += "\\n";
    } else if (char === "\r") {
      output += "\\r";
    } else if (char === "\t") {
      output += "\\t";
    } else if (isHiddenCodePoint(cp) || /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u.test(char) || (/\p{Zs}/u.test(char) && char !== " ")) {
      output += `\\u{${cp.toString(16).toUpperCase()}}`;
    } else {
      output += char;
    }
  }
  return output;
}

/**
 * Walks tool or descriptor metadata and reports defaults, enums and examples that would turn off
 * a safety control (for example a CLI flag that disables a sandbox).
 */
export function findDangerousDefaults(value: unknown, extraPatterns: string[] = []): DangerousDefaultFinding[] {
  const patterns = [...DEFAULT_DANGEROUS_PATTERNS, ...extraPatterns].map((pattern) => pattern.toLowerCase());
  const findings: DangerousDefaultFinding[] = [];
  const visit = (node: unknown, path: string, depth: number, inValueSlot: boolean): void => {
    if (depth > 32 || findings.length >= 64) return;
    if (typeof node === "string") {
      if (inValueSlot) {
        const lowered = stripHiddenUnicode(node).toLowerCase();
        if (patterns.some((pattern) => lowered.includes(pattern))) {
          findings.push({ path, value: escapeNonPrinting(node.slice(0, 120)) });
        }
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => visit(item, `${path}[${index}]`, depth + 1, inValueSlot));
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const childPath = `${path}.${key}`;
      if (DANGEROUS_BOOLEAN_KEYS.test(key) && child && typeof child === "object" && (child as Record<string, unknown>).default === true) {
        findings.push({ path: `${childPath}.default`, value: "true" });
      }
      const valueSlot = inValueSlot || key === "default" || key === "enum" || key === "examples" || key === "const";
      visit(child, childPath, depth + 1, valueSlot);
    }
  };
  visit(value, "$", 0, false);
  return findings;
}
