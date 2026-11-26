import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, it, vi } from "vitest";
import { parseConfig } from "./config.js";
import { extractArgumentFields } from "./arguments.js";
import { checkProtectedPaths, isWorkspacePath, protectedWriteDiff, resolveArgumentPath } from "./protected-paths.js";
import { matchesPathGlob } from "@palizade/policy";

it.skipIf(process.platform !== "win32")("treats Windows path aliases as critical or uncertain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-paths-"));
  try {
    const config = parseConfig("{}", dir);
    for (const path of ["package.json", ".git/hooks/pre-commit", "CLAUDE.md", ".mcp.json"]) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await writeFile(join(dir, path), "test fixture");
    }
    const check = (path: string) => checkProtectedPaths(extractArgumentFields({ path }), dir, config);
    expect.soft(check("GIT~1\\hooks\\pre-commit").critical).toBe(true);
    for (const path of [
      "PACKAG~1.JSO", "CLAUDE~1.MD", "MCP~1.JSO", "package.json::$DATA",
      ".git\\hooks\\pre-commit::$DATA", "CLAUDE.md::$DATA", ".mcp.json::$DATA",
      "package.json.", "folder.\\file", "package.json ", "C:package.json", "file.txt:stream",
      "\\\\server\\share\\file", "\\\\?\\C:\\file", "//./C:/file", "\\??\\Volume\\file", "file://server/share/file", "unknown~1/file.txt"
    ]) {
      const { critical, resolved: [resolved] } = check(path);
      expect.soft(critical, path).toBe(true);
      expect.soft(resolved?.uncertain, path).toBe(true);
      expect.soft(isWorkspacePath(resolved!, dir), path).toBe(false);
    }
    const normal = resolveArgumentPath("src/app.ts", dir);
    expect(isWorkspacePath(normal, dir)).toBe(true);
    expect(protectedWriteDiff(join(dir, "package.json::$DATA"), {}, 1024, false, () => false))
      .toBe("Target path could not be safely canonicalized; review the raw path before approving.");
  } finally { await rm(dir, { recursive: true, force: true }); }
});

it.each([" ", "a\u007fb", "file://[", "file:///a%00b"])("rejects unsafe input %j without throwing", (input) => {
  expect(resolveArgumentPath(input, tmpdir()).uncertain).toBe(true);
});

it.skipIf(process.platform === "win32")("follows symlinks before resolving a parent segment", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-paths-"));
  try {
    const workspace = join(dir, "workspace");
    const target = join(dir, "outside", "nested");
    await mkdir(workspace);
    await mkdir(target, { recursive: true });
    await symlink(target, join(workspace, "alias"), "dir");
    const resolved = resolveArgumentPath("alias/../.zshenv", workspace);
    expect(resolved.canonical).toBe(join(dir, "outside", ".zshenv"));
    expect(isWorkspacePath(resolved, workspace)).toBe(false);
    expect(resolveArgumentPath("missing/../file.txt", workspace).uncertain).toBe(true);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

it("protects auto-run files, agent instructions and the managed seal directory", () => {
  const dir = tmpdir();
  const sealDir = join(dir, "managed[seal]");
  vi.stubEnv("PALIZADE_SEAL_PATH", join(sealDir, "checkpoint.json"));
  try {
    const config = parseConfig("{}", dir);
    for (const path of [
      ".npmrc", "~/.npmrc", ".pnpmfile.cjs", ".yarnrc.yml", ".yarnrc", "conftest.py", ".pre-commit-config.yaml",
      "lefthook.yml", ".lefthook.yml", ".git/modules/lib/hooks/pre-commit", ".github/actions/check/action.yml",
      ".devcontainer/devcontainer.json", ".vscode/launch.json", "app.code-workspace",
      "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/task.cmd", "~/.gitconfig", "~/.netrc", "~/.git-credentials",
      "CLAUDE.local.md", ".cursorrules", ".windsurfrules", ".clinerules", "GEMINI.md", ".github/copilot-instructions.md",
      sealDir, join(sealDir, "checkpoint.json"), join(sealDir, "nested", "other.txt")
    ]) expect.soft(checkProtectedPaths(extractArgumentFields({ path }), dir, config).critical, path).toBe(true);
    expect(checkProtectedPaths(extractArgumentFields({ path: join(dir, "manageds", "other.txt") }), dir, config).critical).toBe(false);
  } finally { vi.unstubAllEnvs(); }
});

it("protects traversal, home targets and symlink ancestors without blocking normal source files", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-paths-"));
  try {
    const config = parseConfig("protectedTargets: { outputDirectory: output }\n", dir);
    const check = (path: string) => checkProtectedPaths(extractArgumentFields({ path }), dir, config);
    expect(check(".vscode/settings.json").critical).toBe(true);
    expect(check(".worktrees/lane-a/.claude/settings.json").critical).toBe(true);
    expect(check(".worktrees/lane-a/.github/workflows/.hidden/build.yml").critical).toBe(true);
    expect(check(".worktrees/lane-a/src/app.ts").critical).toBe(false);
    expect(check("../.github/workflows/x.yml").critical).toBe(true);
    expect(check("~/.ssh/id_rsa").critical).toBe(true);
    expect(check("src/app.ts").critical).toBe(false);
    expect(check("output/result.md").outputAllowed).toBe(true);
    expect(check("output/../outside.md").outputAllowed).toBe(false);
    await mkdir(join(dir, ".vscode"));
    await symlink(join(dir, ".vscode"), join(dir, "alias"), process.platform === "win32" ? "junction" : "dir");
    expect(check("alias/settings.json").critical).toBe(true);
    expect(matchesPathGlob("C:/work/.VSCODE/SETTINGS.JSON", ".vscode/settings.json", true)).toBe(true);
    expect(matchesPathGlob("/work/.VSCODE/SETTINGS.JSON", ".vscode/settings.json", false)).toBe(false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
it("renders capped escaped diffs and masks tainted proposals", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-diff-"));
  try {
    const file = join(dir, "settings.json");
    await writeFile(file, '{"enabled":false}');
    const diff = protectedWriteDiff(file, { content: '{"enabled":true}\u{E0041}' }, 1024, false, () => false);
    expect(diff).toContain('-{"enabled":false}');
    expect(diff).toContain('+{"enabled":true}\\u{E0041}');
    expect(protectedWriteDiff(file, { edits: [{ old_string: "false", new_string: "true" }, { old_string: "enabled", new_string: "active" }] }, 1024, false, () => false)).toContain('+{"active":true}');
    expect(protectedWriteDiff(file, { edits: [{ oldText: "false", newText: "true" }] }, 1024, false, () => false)).toContain('+{"enabled":true}');
    expect(protectedWriteDiff(file, { edits: [{ old_string: "false", new_string: "$&" }] }, 1024, false, () => false)).toContain('+{"enabled":$&}');
    expect(protectedWriteDiff(file, { edits: [{ old_string: "e", new_string: "X", replace_all: true }] }, 1024, false, () => false)).toContain('+{"XnablXd":falsX}');
    expect(() => protectedWriteDiff(file, { edits: [{ old_string: "missing", new_string: "true" }] }, 1024, false, () => false)).toThrow("does not match");
    expect(() => protectedWriteDiff(file, { edits: [{ old_string: "false" }] }, 1024, false, () => false)).toThrow("Invalid critical edit");
    expect(protectedWriteDiff(file, { content: "hidden tainted proposal" }, 1024, true, () => false)).not.toContain("hidden tainted proposal");
    expect(() => protectedWriteDiff(file, { content: "x".repeat(1025) }, 1024, false, () => false)).toThrow("limit");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
it("treats Palizade's own state, wherever it is configured, and Gemini's hook settings as critical", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-self-"));
  try {
    const config = parseConfig("stateDir: .\ntaint: { keyPath: keys/taint.key }\naudit: { jsonl: logs/audit.jsonl, sqlite: logs/audit.sqlite }\n", dir);
    const check = (path: string) => checkProtectedPaths(extractArgumentFields({ path }), dir, config).critical;
    expect(check(".palizade/taint.sqlite")).toBe(true);
    expect(check(".palizade/anything")).toBe(true);
    expect(check("keys/taint.key")).toBe(true);
    expect(check("logs/audit.jsonl")).toBe(true);
    expect(check("logs/audit.sqlite")).toBe(true);
    expect(check("~/.gemini/settings.json")).toBe(true);
    expect(check("logs/build.log")).toBe(false);
    expect(check("src/app.ts")).toBe(false);
    expect(check("listener.token")).toBe(true);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
