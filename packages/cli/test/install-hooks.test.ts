import { describe, expect, it } from "vitest";
import { mergeHookEntries } from "../src/install-hooks.js";

const cliParts = ["C:/node/node.exe", "C:/palizade/dist/index.cjs", "-c", "C:/proj/palizade.yaml", "hook"];

describe("mergeHookEntries", () => {
  it("adds Claude Code PreToolUse/PostToolUse entries without duplicating", () => {
    const settings = { permissions: { allow: [] } };
    const merged = mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, unknown[]>;
    expect(hooks.PreToolUse).toHaveLength(1);
    expect(hooks.PostToolUse).toHaveLength(1);
    expect(hooks.PreToolUse[0]).toMatchObject({ matcher: "Bash|Write|Edit|WebFetch|mcp__.*" });
    const hook = (hooks.PreToolUse[0] as { hooks: Array<{ command: string; args: string[] }> }).hooks[0]!;
    expect(hook.command).toBe("C:/node/node.exe");
    expect(hook.args).toContain("hook");
    expect(hook.args).toContain("claude-code");

    const mergedAgain = mergeHookEntries("claude-code", merged, cliParts, "C:/proj/palizade.yaml");
    expect((mergedAgain.hooks as Record<string, unknown[]>).PreToolUse).toHaveLength(1);
    expect(mergedAgain.permissions).toEqual({ allow: [] });
  });

  it("adds Cursor beforeShellExecution/beforeMCPExecution with failClosed", () => {
    const merged = mergeHookEntries("cursor", {}, cliParts, "C:/proj/palizade.yaml");
    expect(merged.version).toBe(1);
    const hooks = merged.hooks as Record<string, Array<{ command: string; failClosed?: boolean }>>;
    expect(hooks.beforeShellExecution).toHaveLength(1);
    expect(hooks.beforeShellExecution[0]?.failClosed).toBe(true);
    expect(hooks.beforeShellExecution[0]?.command).toContain("hook");
    expect(hooks.beforeMCPExecution[0]?.failClosed).toBe(true);
  });

  it("adds Codex PreToolUse entries with a Bash/apply_patch matcher", () => {
    const merged = mergeHookEntries("codex", {}, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, unknown[]>;
    expect(hooks.PreToolUse[0]).toMatchObject({ matcher: "Bash|apply_patch|mcp__.*" });
    const group = hooks.PreToolUse[0] as { hooks: Array<{ command: string; args: string[] }> };
    expect(group.hooks[0]?.args).toContain("codex");
  });

  it("adds prompt hooks, fails Claude Code tool hooks closed, and updates old entries in place", () => {
    const old = { hooks: { PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch", hooks: [{ type: "command", command: "C:/node/node.exe", args: [...cliParts.slice(1), "claude-code"] }] }] } };
    const merged = mergeHookEntries("claude-code", old, cliParts, "C:/proj/palizade.yaml");
    const hooks = merged.hooks as Record<string, Array<{ hooks: Array<{ args: string[]; onFailure?: string }> }>>;
    expect(hooks.PreToolUse).toHaveLength(1);
    expect(hooks.PreToolUse[0]!.hooks[0]!.onFailure).toBe("block");
    expect(hooks.UserPromptSubmit[0]!.hooks[0]!.args.slice(-2)).toEqual(["claude-code", "UserPromptSubmit"]);
    expect(hooks.UserPromptSubmit[0]!.hooks[0]!.onFailure).toBeUndefined();

    const cursor = mergeHookEntries("cursor", mergeHookEntries("cursor", {}, cliParts, "x"), cliParts, "x");
    const cursorHooks = cursor.hooks as Record<string, Array<{ command: string; failClosed?: boolean }>>;
    expect(cursorHooks.beforeShellExecution).toHaveLength(1);
    expect(cursorHooks.beforeSubmitPrompt).toHaveLength(1);
    expect(cursorHooks.beforeSubmitPrompt[0]!.command.endsWith("cursor beforeSubmitPrompt")).toBe(true);
    expect(cursorHooks.beforeSubmitPrompt[0]!.failClosed).toBeUndefined();

    const codex = mergeHookEntries("codex", {}, cliParts, "x").hooks as Record<string, unknown[]>;
    expect(codex.UserPromptSubmit).toHaveLength(1);
  });

  it("preserves existing hooks and refuses malformed settings", () => {
    const settings = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }] } };
    const merged = mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const pre = (merged.hooks as Record<string, unknown[]>).PreToolUse!;
    expect(pre).toHaveLength(2);
    expect(pre[0]).toMatchObject({ matcher: "Bash" });
  });
});

describe("inspectHooks", () => {
  it("reports missing, outdated and installed entries", async () => {
    const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { inspectHooks } = await import("../src/install-hooks.js");
    const dir = await mkdtemp(join(tmpdir(), "palizade-inspect-hooks-"));
    try {
      const path = join(dir, "settings.json");
      expect((await inspectHooks("claude-code", path)).events.every((entry) => entry.status === "missing")).toBe(true);
      const old = { hooks: { PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch", hooks: [{ type: "command", command: "node", args: ["/x/palizade/dist/index.cjs", "hook", "claude-code"] }] }] } };
      await writeFile(path, JSON.stringify(old));
      const before = Object.fromEntries((await inspectHooks("claude-code", path)).events.map((entry) => [entry.event, entry.status]));
      expect(before).toEqual({ PreToolUse: "outdated", PostToolUse: "missing", UserPromptSubmit: "missing" });
      await writeFile(path, JSON.stringify(mergeHookEntries("claude-code", old, cliParts, "x")));
      expect((await inspectHooks("claude-code", path)).events.every((entry) => entry.status === "installed")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
