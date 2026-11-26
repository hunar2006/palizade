import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { installHooks } from "../src/install-hooks.js";

/**
 * Applies Claude Code hook matcher rules:
 * empty or "*" matches all tools; patterns with regex metacharacters are compiled as
 * unanchored JavaScript RegExp instances; plain lists use exact match.
 */
function matchesClaudeCodeMatcher(matcher: string | undefined, toolName: string): boolean {
  if (matcher === undefined || matcher === "" || matcher === "*") {
    return true;
  }
  if (/[.*+?^${}()[\]\\]/u.test(matcher)) {
    return new RegExp(matcher, "u").test(toolName);
  }
  return matcher.split(/[|,]/u).includes(toolName);
}

async function installClaudeCodeHooks(): Promise<{
  preMatcher: string | undefined;
  postMatcher: string | undefined;
  cleanup: () => Promise<void>;
}> {
  const dir = await mkdtemp(join(tmpdir(), "palizade-install-hooks-repro-"));
  const settingsPath = join(dir, ".claude", "settings.local.json");
  const configPath = join(dir, "palizade.yaml");
  await installHooks("claude-code", { configPath, settingsPath, cwd: dir });
  const settings = JSON.parse(await readFile(settingsPath, "utf8")) as {
    hooks?: {
      PreToolUse?: Array<{ matcher?: string }>;
      PostToolUse?: Array<{ matcher?: string }>;
    };
  };
  return {
    preMatcher: settings.hooks?.PreToolUse?.[0]?.matcher,
    postMatcher: settings.hooks?.PostToolUse?.[0]?.matcher,
    cleanup: async () => rm(dir, { recursive: true, force: true })
  };
}

describe("Claude Code hook matcher repros", () => {
  it.each([
    ["PreToolUse", "NotebookEdit", true],
    ["PreToolUse", "TodoWrite", false],
    ["PreToolUse", "Agent", false],
    ["PreToolUse", "ToolSearch", false],
    ["PreToolUse", "WebSearch", true],
    ["PostToolUse", "PowerShell", true],
    ["PostToolUse", "Bash", true],
    ["PostToolUse", "Agent", true],
    ["PostToolUse", "ReadMcpResourceTool", true],
    ["PostToolUse", "ReadMcpResourceDirTool", true],
    ["PostToolUse", "ListMcpResourcesTool", true],
    ["PostToolUse", "TodoWrite", false],
    ["PostToolUse", "ToolSearch", false],
    ["PostToolUse", "ArchiveRead", false]
  ])("matches %s for %s only as intended", async (event, tool, expected) => {
    const { preMatcher, postMatcher, cleanup } = await installClaudeCodeHooks();
    try {
      expect(matchesClaudeCodeMatcher(event === "PreToolUse" ? preMatcher : postMatcher, tool)).toBe(expected);
    } finally {
      await cleanup();
    }
  });

  it("Claim 1: Claude Code PreToolUse matcher installed by installHooks covers native PowerShell", async () => {
    const { preMatcher, cleanup } = await installClaudeCodeHooks();
    try {
      expect(preMatcher).toBeTypeOf("string");
      for (const expected of ["Bash", "Write", "Edit", "WebFetch", "mcp__demo__send_email"]) {
        expect(matchesClaudeCodeMatcher(preMatcher, expected)).toBe(true);
      }
      const accidentalMatches = ["NotebookEdit", "TodoWrite"].filter((tool) => matchesClaudeCodeMatcher(preMatcher, tool));
      expect(
        matchesClaudeCodeMatcher(preMatcher, "PowerShell"),
        `PreToolUse matcher ${JSON.stringify(preMatcher)} did not match "PowerShell" (accidental unanchored matches: ${accidentalMatches.join(", ") || "none"})`
      ).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("Claim 2: Claude Code PostToolUse matcher installed by installHooks covers native WebSearch", async () => {
    const { postMatcher, cleanup } = await installClaudeCodeHooks();
    try {
      expect(postMatcher).toBeTypeOf("string");
      for (const expected of ["Read", "WebFetch", "Grep", "Glob", "mcp__demo__read_page"]) {
        expect(matchesClaudeCodeMatcher(postMatcher, expected)).toBe(true);
      }
      const accidentalMatches = ["ArchiveRead"].filter((tool) => matchesClaudeCodeMatcher(postMatcher, tool));
      expect(
        matchesClaudeCodeMatcher(postMatcher, "WebSearch"),
        `PostToolUse matcher ${JSON.stringify(postMatcher)} did not match "WebSearch" (accidental unanchored matches: ${accidentalMatches.join(", ") || "none"})`
      ).toBe(true);
    } finally {
      await cleanup();
    }
  });
});
