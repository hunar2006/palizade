import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classifyToolDetailed } from "./classifier.js";
import type { ServerConfig } from "./config.js";
import { catalogEntryFor } from "./tool-catalog.js";
import type { McpTool } from "./mcp.js";

// Tool names and annotations listed from real servers (`pnpm eval:real`), so catalog entries are
// checked against what those servers actually expose.
const fixture = JSON.parse(readFileSync(new URL("./real-server-tools.fixture.json", import.meta.url), "utf8")) as Record<string, { command: string; args: string[]; tools: McpTool[] }>;

const base: ServerConfig = {
  command: "npx", args: [], env: {}, headers: {}, protocolVersion: "auto", trust: "untrusted",
  toolClasses: {}, toolCapabilities: {}, argumentRoles: {}, sensitive: false, sensitiveTools: {}, sensitivePathPatterns: [], shell: false, allowShell: false
};

describe("catalog against real tool lists", () => {
  for (const [name, entry] of Object.entries(fixture)) {
    it(`classifies every ${name} tool from the catalog`, () => {
      const server = { ...base, command: entry.command, args: entry.args };
      expect(catalogEntryFor(server)?.id).toBe(name);
      const uncovered = entry.tools.filter((tool) => !classifyToolDetailed(tool.name, server, tool).reasons.some((reason) => reason.startsWith("catalog:")));
      expect(uncovered.map((tool) => tool.name)).toEqual([]);
    });
  }

  it("keeps search tools as sources and fetch tools as checked sinks", () => {
    const at = (name: string, tool: string) => {
      const entry = fixture[name]!;
      return classifyToolDetailed(tool, { ...base, command: entry.command, args: entry.args }, entry.tools.find((candidate) => candidate.name === tool));
    };
    expect(at("exa", "web_search_exa").toolClass).toBe("source");
    expect(at("exa", "web_fetch_exa")).toMatchObject({ toolClass: "sink", argumentRoles: { "urls[*]": "url" } });
    expect(at("notion", "API-post-search").toolClass).toBe("source");
    expect(at("notion", "API-patch-page").toolClass).toBe("sink");
    expect(at("mongodb", "drop-database").capabilities).toContain("deletes_data");
    expect(at("desktop-commander", "start_process").capabilities).toContain("executes_code");
  });
});
