import { closeSync, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { matchesPathGlob } from "@palizade/policy";
import { maskKnownSensitiveText } from "@palizade/detectors";
import type { ArgumentField } from "./arguments.js";
import type { PalizadeConfig } from "./config.js";

export const CRITICAL_PATHS = [
  ".claude/**", "~/.claude.json", "~/.claude/**", ".mcp.json", ".cursor/**", "~/.cursor/**", ".codex/**", "~/.codex/**",
  ".vscode/settings.json", ".vscode/tasks.json", ".github/workflows/**", ".gitlab-ci.yml", ".git/hooks/**", ".git/config", ".husky/**",
  "package.json", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile", "**/PowerShell/**/*profile*.ps1", "**/WindowsPowerShell/**/*profile*.ps1", "**/Microsoft.PowerShell_profile.ps1", "**/profile.ps1",
  "~/Library/LaunchAgents/**", "~/.config/systemd/user/**", "CLAUDE.md", "AGENTS.md", ".env*", "~/.ssh/**", "~/.aws/**",
  "palizade.yaml", "palizade.allow.yaml", "palizade.lock", "~/.config/Claude/claude_desktop_config.json", "~/Library/Application Support/Claude/claude_desktop_config.json",
  "**/Claude/claude_desktop_config.json"
];

export interface ResolvedArgumentPath { logical: string; canonical: string; uncertain: boolean }

export function resolveArgumentPath(input: string, cwd: string): ResolvedArgumentPath {
  if (!input.trim() || /[\u0000-\u001F]/u.test(input)) return { logical: input, canonical: input, uncertain: true };
  const expanded = input.startsWith("file:") ? fileURLToPath(input) : input.replace(/\\/gu, "/").replace(/^~(?=\/|$)/u, homedir());
  const logical = resolve(cwd, expanded);
  let ancestor = logical;
  const suffix: string[] = [];
  for (;;) {
    try { return { logical, canonical: resolve(realpathSync(ancestor), ...suffix), uncertain: false }; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return { logical, canonical: logical, uncertain: true };
      const parent = dirname(ancestor);
      if (parent === ancestor) return { logical, canonical: logical, uncertain: true };
      suffix.unshift(relative(parent, ancestor));
      ancestor = parent;
    }
  }
}

export function checkProtectedPaths(fields: ArgumentField[], cwd: string, config: PalizadeConfig): { critical: boolean; paths: string[]; resolved: ResolvedArgumentPath[]; outputAllowed: boolean } {
  const resolved = fields.filter((field) => field.role === "file_path").map((field) => resolveArgumentPath(field.text, cwd));
  const patterns = [...CRITICAL_PATHS, ...config.protectedTargets.criticalPaths, config.lockfile, config.egress.learnedFile, config.policy];
  const paths = [...new Set(resolved.flatMap((path) => [path.logical, path.canonical]))];
  const critical = resolved.some((path) => path.uncertain || patterns.some((pattern) => matchesPathGlob(path.logical, pattern) || matchesPathGlob(path.canonical, pattern)));
  const output = config.protectedTargets.outputDirectory ? resolveArgumentPath(config.protectedTargets.outputDirectory, cwd) : undefined;
  const insensitive = process.platform === "win32" || process.platform === "darwin";
  const fold = (path: string) => insensitive ? path.toLowerCase() : path;
  const outputAllowed = Boolean(output && !output.uncertain && resolved.length && resolved.every((path) => {
    const delta = relative(fold(output!.canonical), fold(path.canonical));
    return !path.uncertain && delta !== ".." && !delta.startsWith(`..${sep}`) && !isAbsolute(delta);
  }));
  return { critical, paths, resolved, outputAllowed };
}

export function escapeNonPrinting(text: string): string {
  return text.replace(/[\u0000-\u0009\u000B-\u001F\u007F\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu, (char) => `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}`);
}

function readCapped(path: string, maxBytes: number): string {
  let fd: number;
  try { fd = openSync(path, "r"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return ""; throw error; }
  try {
    if (!fstatSync(fd).isFile()) throw new Error("Critical target is not a regular file");
    const buffer = Buffer.alloc(maxBytes + 1);
    const size = readSync(fd, buffer, 0, buffer.length, 0);
    if (size > maxBytes) throw new Error("Critical path diff size limit exceeded");
    return buffer.subarray(0, size).toString("utf8");
  } finally { closeSync(fd); }
}

export function protectedWriteDiff(path: string, args: unknown, maxBytes: number, tainted: boolean, mask: (text: string) => boolean): string {
  const before = readCapped(path, maxBytes);
  const value = args && typeof args === "object" ? args as Record<string, unknown> : {};
  let after = [value.content, value.text, value.body].find((item): item is string => typeof item === "string");
  if (Array.isArray(value.edits)) {
    after = before;
    for (const edit of value.edits) {
      if (!edit || typeof edit.oldText !== "string" || typeof edit.newText !== "string") throw new Error("Invalid critical edit");
      if (!after.includes(edit.oldText)) throw new Error("Critical edit does not match current content");
      after = after.replace(edit.oldText, edit.newText);
    }
  }
  const oldText = typeof value.old_string === "string" ? value.old_string : typeof value.oldText === "string" ? value.oldText : undefined;
  const newText = typeof value.new_string === "string" ? value.new_string : typeof value.newText === "string" ? value.newText : undefined;
  if (oldText !== undefined && newText !== undefined) {
    if (!before.includes(oldText)) throw new Error("Critical edit does not match current content");
    after = before.replace(oldText, newText);
  }
  if (after === undefined) return "No complete replacement content was supplied; review the critical target operation.";
  if (Buffer.byteLength(after) > maxBytes) throw new Error("Critical path diff size limit exceeded");
  const safe = (text: string, redact: boolean) => escapeNonPrinting(redact || mask(text) ? "[REDACTED:tainted-or-sensitive-content]" : maskKnownSensitiveText(text));
  const old = safe(before, false), next = safe(after, tainted);
  return old === next ? "No visible change after masking." : `--- current\n+++ proposed\n${old.split("\n").map((line) => `-${line}`).join("\n")}\n${next.split("\n").map((line) => `+${line}`).join("\n")}`;
}
