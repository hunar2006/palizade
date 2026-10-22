import { describe, expect, it } from "vitest";
import { describeServerTools, formatServerTools } from "./tools-command.js";

const base = { args: [], env: {}, headers: {}, protocolVersion: "auto" as const, toolClasses: {}, toolCapabilities: {}, argumentRoles: {}, sensitive: false, sensitiveTools: {}, sensitivePathPatterns: [], shell: false, allowShell: false };

describe("palizade tools", () => {
  it("classifies locked tools without starting servers and flags unknown ones", () => {
    const config = {
      servers: {
        fs: { ...base, command: "npx", args: ["@modelcontextprotocol/server-filesystem"], trust: "untrusted" as const },
        custom: { ...base, command: "node", trust: "untrusted" as const },
        fresh: { ...base, command: "node", trust: "semi" as const }
      }
    };
    const lock = {
      version: 1,
      servers: {
        fs: { tools: { directory_tree: { hash: "h", approvedAt: "t", snapshot: { name: "directory_tree" } } } },
        custom: { tools: { frobnicate: { hash: "h", approvedAt: "t", snapshot: { name: "frobnicate", description: "Reads things" } } } }
      }
    };
    const reports = describeServerTools(config as never, lock as never);
    expect(reports.map((report) => [report.server, report.catalog])).toEqual([["fs", "filesystem"], ["custom", undefined], ["fresh", undefined]]);
    expect(reports[0]!.tools[0]).toMatchObject({ tool: "directory_tree", toolClass: "source", reasons: ["catalog:filesystem"] });
    const text = formatServerTools(reports);
    expect(text).toContain("1 unknown tool(s): blocked by the default policy");
    expect(text).toContain("no locked tools; run palizade lock approve fresh");
    expect(() => describeServerTools(config as never, lock as never, "nope")).toThrow("Unknown server");
  });
});
