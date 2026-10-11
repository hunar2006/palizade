import { describe, expect, it } from "vitest";
import { classifyToolDetailed } from "./classifier.js";
import type { ServerConfig } from "./config.js";

describe("classifyToolDetailed", () => {
  const server: ServerConfig = {
    command: "node",
    args: [],
    env: {},
    headers: {},
    protocolVersion: "auto",
    trust: "semi",
    toolClasses: {},
    toolCapabilities: {}, argumentRoles: {},
    sensitive: false,
    sensitiveTools: {},
    sensitivePathPatterns: [],
    shell: false,
    allowShell: false
  };

  it("derives network, message, and file-write capabilities from names and annotations", () => {
    expect(classifyToolDetailed("http_post", server).capabilities).toEqual(expect.arrayContaining(["network_egress"]));
    expect(classifyToolDetailed("send_email", server).capabilities).toEqual(expect.arrayContaining(["sends_message", "network_egress"]));
    expect(classifyToolDetailed("write_file", server).capabilities).toEqual(expect.arrayContaining(["file_write", "writes_local"]));
    expect(classifyToolDetailed("custom", server, { name: "custom", inputSchema: {}, annotations: { destructiveHint: true } }).capabilities)
      .toEqual(expect.arrayContaining(["file_write", "writes_local", "writes_remote"]));
  });

  it("classifies camelCase and money-moving tool names", () => {
    for (const name of ["GmailSendEmail", "GitHubDeleteRepository", "BinancePlaceOrder", "BinanceWithdraw", "BankTransferFunds"]) {
      expect(classifyToolDetailed(name, server).toolClass, name).toBe("sink");
    }
    for (const name of ["GitHubGetUserDetails", "EvernoteManagerSearchNotes"]) {
      expect(classifyToolDetailed(name, server).toolClass, name).toBe("source");
    }
  });

  it("allows annotations to lower risk only on trusted servers", () => {
    const tool = { name: "send_email", inputSchema: {}, annotations: { readOnlyHint: true } };
    expect(classifyToolDetailed(tool.name, { ...server, trust: "untrusted" }, tool).toolClass).toBe("sink");
    expect(classifyToolDetailed(tool.name, server, tool).toolClass).toBe("sink");
    expect(classifyToolDetailed(tool.name, { ...server, trust: "trusted" }, tool).toolClass).toBe("source");
    expect(classifyToolDetailed("read_file", server, { name: "read_file", inputSchema: {}, annotations: { destructiveHint: true } }).toolClass).toBe("sink");
    expect(classifyToolDetailed("custom", server, { name: "custom", inputSchema: {}, annotations: { readOnlyHint: true } }).toolClass).toBe("unknown");
  });
});
