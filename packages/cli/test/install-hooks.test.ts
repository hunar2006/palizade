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
    expect(hooks.PreToolUse[0]).toMatchObject({ matcher: "Bash|Write|Edit|WebFetch" });
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

  it("preserves existing hooks and refuses malformed settings", () => {
    const settings = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }] } };
    const merged = mergeHookEntries("claude-code", settings, cliParts, "C:/proj/palizade.yaml");
    const pre = (merged.hooks as Record<string, unknown[]>).PreToolUse!;
    expect(pre).toHaveLength(2);
    expect(pre[0]).toMatchObject({ matcher: "Bash" });
  });
});
