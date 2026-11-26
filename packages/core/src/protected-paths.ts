import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
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
  "palizade.yaml", "palizade.allow.yaml", "palizade.lock", ".palizade/**", "**/node_modules/palizade/**", ".gemini/settings.json", "~/.gemini/settings.json", "~/.config/Claude/claude_desktop_config.json", "~/Library/Application Support/Claude/claude_desktop_config.json",
  "**/Claude/claude_desktop_config.json",
  ".npmrc", "~/.npmrc", ".pnpmfile.cjs", ".yarnrc.yml", ".yarnrc", "conftest.py", ".pre-commit-config.yaml", "lefthook.yml", ".lefthook.yml", ".git/modules/**/hooks/**", ".github/actions/**",
  ".devcontainer/**", ".vscode/launch.json", "*.code-workspace", "**/Microsoft/Windows/Start Menu/Programs/Startup/**", "~/.gitconfig", "~/.netrc", "~/.git-credentials",
  "CLAUDE.local.md", ".cursorrules", ".windsurfrules", ".clinerules", "GEMINI.md", ".github/copilot-instructions.md"
];

const shortName = /~\d/u;

function nativePath(path: string): string {
  const resolved = realpathSync.native(path);
  return process.platform === "win32" ? resolved.replace(/^\\\\\?\\UNC\\/iu, "\\\\").replace(/^\\\\\?\\/u, "") : resolved;
}

function unsafePath(path: string): boolean {
  if (!path.trim() || /[\u0000-\u001F\u007F]/u.test(path)) return true;
  if (process.platform !== "win32") return false;
  return /^[\\/]{2}|^[\\/]\?\?[\\/]|^[a-z]:(?![\\/])/iu.test(path) || path.replace(/^[a-z]:/iu, "").includes(":") ||
    path.split(/[\\/]/u).some((segment) => segment !== "." && segment !== ".." && /[. ]$/u.test(segment));
}

export interface ResolvedArgumentPath { logical: string; canonical: string; uncertain: boolean }

export function isWorkspacePath(path: ResolvedArgumentPath, cwd: string): boolean {
  try {
    if (unsafePath(cwd)) return false;
    const canonical = nativePath(cwd);
    return !(process.platform === "win32" && shortName.test(canonical)) && isWithinDirectory(path, canonical);
  } catch { return false; }
}

function isWithinDirectory(path: ResolvedArgumentPath, directory: string): boolean {
  if (path.uncertain) return false;
  const insensitive = process.platform === "win32" || process.platform === "darwin";
  const fold = (value: string) => insensitive ? value.toLowerCase() : value;
  const delta = relative(fold(directory), fold(path.canonical));
  return delta !== ".." && !delta.startsWith(".." + sep) && !isAbsolute(delta);
}

export function resolveArgumentPath(input: string, cwd: string): ResolvedArgumentPath {
  // The diff caller receives only a path string, so keep unsafe spellings intact.
  const uncertain = { logical: input, canonical: input, uncertain: true };
  const fileUrl = /^file:/iu.test(input);
  if (fileUrl ? /[\u0000-\u001F\u007F]/u.test(input) : unsafePath(input)) return uncertain;
  let expanded: string;
  try {
    expanded = fileUrl ? fileURLToPath(input) : input.replace(/\\/gu, "/").replace(/^~(?=\/|$)/u, homedir());
  } catch { return uncertain; }
  const windows = process.platform === "win32";
  if (unsafePath(expanded) || (!isAbsolute(expanded) && unsafePath(cwd))) return uncertain;
  if (windows && shortName.test(expanded.split(/[\\/]/u).filter(Boolean).at(-1) ?? "")) return uncertain;
  const logical = resolve(cwd, expanded);
  let physical = logical;
  const components = expanded.split("/");
  const lastParent = components.lastIndexOf("..");
  if (!windows && lastParent !== -1) {
    try {
      let prefix = isAbsolute(expanded) ? sep : nativePath(cwd);
      for (const part of components.slice(0, lastParent + 1)) {
        if (!part || part === ".") continue;
        prefix = part === ".." ? dirname(prefix) : nativePath(join(prefix, part));
        if (!statSync(prefix).isDirectory()) return uncertain;
      }
      physical = join(prefix, ...components.slice(lastParent + 1));
    } catch { return uncertain; }
  }
  let ancestor = physical;
  const suffix: string[] = [];
  for (;;) {
    try {
      const canonical = resolve(nativePath(ancestor), ...suffix);
      return windows && shortName.test(canonical) ? uncertain : { logical, canonical, uncertain: false };
    }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return uncertain;
      // A dangling link is an existing path whose eventual target is unknown.
      try {
        if (lstatSync(ancestor, { throwIfNoEntry: false })) return uncertain;
      } catch { return uncertain; }
      const parent = dirname(ancestor);
      if (parent === ancestor) return uncertain;
      suffix.unshift(relative(parent, ancestor));
      ancestor = parent;
    }
  }
}

export function checkProtectedPaths(fields: ArgumentField[], cwd: string, config: PalizadeConfig, includeDirectoryRoots = false): { critical: boolean; paths: string[]; resolved: ResolvedArgumentPath[]; outputAllowed: boolean } {
  const resolved = fields.filter((field) => field.role === "file_path").map((field) => resolveArgumentPath(field.text, cwd));
  // Palizade's own state files count too, wherever the config puts them. Not all of stateDir: it may be the project root.
  const patterns = [...CRITICAL_PATHS, ...config.protectedTargets.criticalPaths, config.lockfile, config.egress.learnedFile, config.policy,
    config.audit.jsonl, config.audit.sqlite, config.taint.sqlite, config.taint.keyPath, join(config.stateDir, "listener.token")];
  if (includeDirectoryRoots) {
    patterns.push(...patterns.filter((pattern) => /[\\/]\*\*$/u.test(pattern)).map((pattern) => pattern.slice(0, -3)));
  }
  const managed = process.env.PALIZADE_SEAL_PATH;
  const sealDirectories = managed ? [dirname(resolve(managed)), dirname(resolveArgumentPath(managed, process.cwd()).canonical)] : [];
  const paths = [...new Set(resolved.flatMap((path) => [path.logical, path.canonical]))];
  const critical = resolved.some((path) => path.uncertain || patterns.some((pattern) => matchesPathGlob(path.logical, pattern) || matchesPathGlob(path.canonical, pattern)) ||
    sealDirectories.some((directory) => isWithinDirectory(path, directory) || isWithinDirectory({ ...path, canonical: path.logical }, directory)));
  const output = config.protectedTargets.outputDirectory ? resolveArgumentPath(config.protectedTargets.outputDirectory, cwd) : undefined;
  const outputAllowed = Boolean(output && !output.uncertain && resolved.length && resolved.every((path) => isWithinDirectory(path, output.canonical)));
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
  const target = isAbsolute(path) && resolveArgumentPath(path, process.cwd());
  if (!target || target.uncertain) return "Target path could not be safely canonicalized; review the raw path before approving.";
  const before = readCapped(target.canonical, maxBytes);
  const value = args && typeof args === "object" ? args as Record<string, unknown> : {};
  let after = [value.content, value.text, value.body].find((item): item is string => typeof item === "string");
  if (Array.isArray(value.edits)) {
    after = before;
    for (const edit of value.edits) {
      const oldText = typeof edit?.old_string === "string" ? edit.old_string : edit?.oldText;
      const newText = typeof edit?.new_string === "string" ? edit.new_string : edit?.newText;
      if (typeof oldText !== "string" || typeof newText !== "string") throw new Error("Invalid critical edit");
      if (!after.includes(oldText)) throw new Error("Critical edit does not match current content");
      after = edit.replace_all ? after.replaceAll(oldText, () => newText) : after.replace(oldText, () => newText);
    }
  }
  const oldText = typeof value.old_string === "string" ? value.old_string : typeof value.oldText === "string" ? value.oldText : undefined;
  const newText = typeof value.new_string === "string" ? value.new_string : typeof value.newText === "string" ? value.newText : undefined;
  if (oldText !== undefined && newText !== undefined) {
    if (!before.includes(oldText)) throw new Error("Critical edit does not match current content");
    after = before.replace(oldText, () => newText);
  }
  // shortcut: unfamiliar edit formats cannot produce a full diff, add adapters when a supported tool supplies another edit format.
  if (after === undefined) return "No complete replacement content was supplied; review the critical target operation.";
  if (Buffer.byteLength(after) > maxBytes) throw new Error("Critical path diff size limit exceeded");
  const safe = (text: string, redact: boolean) => escapeNonPrinting(redact || mask(text) ? "[REDACTED:tainted-or-sensitive-content]" : maskKnownSensitiveText(text));
  const old = safe(before, false), next = safe(after, tainted);
  return old === next ? "No visible change after masking." : `--- current\n+++ proposed\n${old.split("\n").map((line) => `-${line}`).join("\n")}\n${next.split("\n").map((line) => `+${line}`).join("\n")}`;
}
