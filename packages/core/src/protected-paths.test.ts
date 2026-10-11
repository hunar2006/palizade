import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parseConfig } from "./config.js";
import { extractArgumentFields } from "./arguments.js";
import { checkProtectedPaths, protectedWriteDiff } from "./protected-paths.js";
import { matchesPathGlob } from "@palizade/policy";

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
