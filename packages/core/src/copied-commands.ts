import { stripHiddenUnicode } from "@palizade/detectors";
import { isPlainRelativeWorkspacePath, isSafeInspectionShellCommand } from "./hooks.js";

export const COPIED_COMMAND_ALLOWLIST = [
  "node --test",
  "npm test",
  "pnpm test",
  "yarn test",
  "bun test",
  "pytest",
  "vitest",
  "jest",
  "cargo test",
  "go test",
  "tsc --noEmit",
  "eslint",
  "git status",
  "git diff",
  "git log",
  "ls",
  "cat"
] as const;

// Flags a copied test runner, typecheck or lint command may carry. Any other flag takes it off the short list.
export const COPIED_COMMAND_FLAGS: Readonly<Record<string, { flags: readonly string[]; filters: readonly string[] }>> = {
  node: { flags: [], filters: ["--test-name-pattern"] },
  npm: { flags: ["--silent"], filters: [] },
  pnpm: { flags: ["--silent"], filters: [] },
  yarn: { flags: ["--silent"], filters: [] },
  bun: { flags: ["--bail"], filters: ["-t", "--test-name-pattern"] },
  cargo: { flags: ["-q", "--quiet", "-v", "--verbose"], filters: [] },
  go: { flags: ["-v", "-failfast", "-count=1"], filters: ["-run"] },
  pytest: { flags: ["-q", "--quiet", "-v", "-vv", "--verbose", "-x", "--exitfirst"], filters: ["-k"] },
  vitest: { flags: ["--run", "--silent", "--bail=1"], filters: ["-t"] },
  jest: { flags: ["--silent", "--verbose", "--bail", "--watchAll=false"], filters: ["-t", "--test-name-pattern"] },
  tsc: { flags: ["--noEmit", "--pretty"], filters: [] },
  eslint: { flags: ["--quiet", "--max-warnings=0"], filters: [] }
};

const TWO_WORD_TEST_RUNNERS = new Map<string, string>([
  ["node", "--test"],
  ["npm", "test"],
  ["pnpm", "test"],
  ["yarn", "test"],
  ["bun", "test"],
  ["cargo", "test"],
  ["go", "test"]
]);

const SINGLE_WORD_RUNNERS = new Set(["pytest", "vitest", "jest", "tsc", "eslint"]);
const GIT_INSPECTION_SUBCOMMANDS = new Set(["status", "diff", "log"]);
const LISTING_ALIASES = new Set(["ls", "dir", "get-childitem", "gci"]);
const FILE_READ_ALIASES = new Set(["cat", "type", "get-content", "gc", "head", "tail"]);

const FLAG_RE = /^--?[a-zA-Z0-9][a-zA-Z0-9._-]*(=[^\s"'`$;&|<>(){}]*)?$/u;
const FILTER_VALUE_RE = /^[a-zA-Z0-9_.: -]+$/u;

interface ShellToken {
  raw: string;
  value: string;
  quoted: boolean;
}

function tokenizeCommand(input: string): ShellToken[] | undefined {
  const tokens: ShellToken[] = [];
  let index = 0;
  while (index < input.length) {
    while (index < input.length && input[index] === " ") index++;
    if (index >= input.length) break;
    const ch = input[index]!;
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = index;
      index++;
      const valueStart = index;
      while (index < input.length && input[index] !== quote) index++;
      if (index >= input.length) return undefined;
      const value = input.slice(valueStart, index);
      index++;
      if (index < input.length && input[index] !== " ") return undefined;
      if (value.length === 0) return undefined;
      tokens.push({ raw: input.slice(start, index), value, quoted: true });
      continue;
    }
    const start = index;
    while (index < input.length && input[index] !== " ") {
      if (input[index] === '"' || input[index] === "'") return undefined;
      index++;
    }
    const raw = input.slice(start, index);
    tokens.push({ raw, value: raw, quoted: false });
  }
  return tokens;
}

function isValidFilterValue(value: string): boolean {
  return value.length > 0 && !value.startsWith("-") && FILTER_VALUE_RE.test(value) && !value.includes("..");
}

function isAllowedGoPattern(arg: string, cwd: string): boolean {
  if (arg === "./...") return true;
  if (!arg.startsWith("./") || !arg.endsWith("/...")) return false;
  const prefix = arg.slice(0, -4);
  return prefix.length > 2 && isPlainRelativeWorkspacePath(prefix, cwd, true);
}

export function isAllowedCopiedLocalCommand(command: string, cwd = process.cwd()): boolean {
  if (typeof command !== "string") return false;
  if (stripHiddenUnicode(command) !== command) return false;
  const trimmed = command.trim();
  if (!trimmed || /[\u0000-\u001F\u007F]/u.test(trimmed)) return false;

  // Strip only the two allowed trailing suffixes from the right in order.
  let body = trimmed.replace(/\s*\|\s*out-string$/iu, "").trimEnd();
  body = body.replace(/\s+2>&1$/u, "").trimEnd();
  if (!body) return false;
  if (/[|<>`$;{}()&]/u.test(body) || /%[^%]+%/u.test(body)) return false;

  const tokens = tokenizeCommand(body);
  if (!tokens || tokens.length === 0) return false;
  const first = tokens[0]!;
  if (first.quoted || /[\\/=\^]/u.test(first.raw)) return false;
  const verb = first.value.replace(/\.(?:exe|cmd)$/iu, "").toLowerCase();

  if (verb === "git") {
    const second = tokens[1];
    if (!second || second.quoted || second.raw.includes("^")) return false;
    if (!GIT_INSPECTION_SUBCOMMANDS.has(second.value.toLowerCase())) return false;
    return isSafeInspectionShellCommand(body, cwd);
  }
  if (LISTING_ALIASES.has(verb) || FILE_READ_ALIASES.has(verb)) {
    return isSafeInspectionShellCommand(body, cwd);
  }

  let argStart: number;
  const requiredSecond = TWO_WORD_TEST_RUNNERS.get(verb);
  if (requiredSecond !== undefined) {
    const second = tokens[1];
    if (!second || second.quoted || second.raw.includes("^")) return false;
    const matched = requiredSecond === "--test"
      ? second.value === "--test"
      : second.value.toLowerCase() === requiredSecond;
    if (!matched) return false;
    argStart = 2;
  } else if (SINGLE_WORD_RUNNERS.has(verb)) {
    argStart = 1;
  } else {
    return false;
  }

  const allowed = COPIED_COMMAND_FLAGS[verb]!;
  const isGoTest = verb === "go";
  const requiresNoEmit = verb === "tsc";
  let afterDashDash = false;
  let sawNoEmit = false;

  for (let i = argStart; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (!afterDashDash && !token.quoted && token.value === "--") {
      afterDashDash = true;
      continue;
    }
    if (!afterDashDash && token.value.startsWith("-")) {
      if (token.quoted || !FLAG_RE.test(token.value)) return false;
      if (allowed.flags.includes(token.value)) {
        if (requiresNoEmit && token.value === "--noEmit") {
          if (/^(?:true|false)$/iu.test(tokens[i + 1]?.value ?? "")) return false;
          sawNoEmit = true;
        }
        continue;
      }
      const eq = token.value.indexOf("=");
      if (!allowed.filters.includes(eq === -1 ? token.value : token.value.slice(0, eq))) return false;
      if (eq !== -1) {
        if (!isValidFilterValue(token.value.slice(eq + 1))) return false;
      } else {
        const next = tokens[++i];
        if (!next || (!next.quoted && next.value === "--")) return false;
        if (!isValidFilterValue(next.value)) return false;
      }
      continue;
    }
    if (isGoTest && isAllowedGoPattern(token.value, cwd)) continue;
    if (isPlainRelativeWorkspacePath(token.raw, cwd, true)) continue;
    return false;
  }

  return !requiresNoEmit || sawNoEmit;
}
