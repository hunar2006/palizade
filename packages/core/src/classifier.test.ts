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
  it("classifies memory and vector writes as persistent sinks", () => {
    for (const name of ["create_entities", "add_observations", "create_relations", "add_memory", "store_memory", "remember", "save_note", "upsert", "write_vector_store"]) {
      expect(classifyToolDetailed(name, server).capabilities, name).toContain("persists_memory");
      expect(classifyToolDetailed(name, server).toolClass, name).toBe("sink");
    }
    expect(classifyToolDetailed("get_memory", server).capabilities).not.toContain("persists_memory");
  });

  it("uses the catalog for known servers chosen in config", () => {
    const fs = { ...server, trust: "untrusted" as const, command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/work"] };
    expect(classifyToolDetailed("directory_tree", fs)).toMatchObject({ toolClass: "source", reasons: ["catalog:filesystem"] });
    expect(classifyToolDetailed("write_file", fs).toolClass).toBe("sink");
    expect(classifyToolDetailed("write_file", fs).argumentRoles).toMatchObject({ path: "file_path" });
    expect(classifyToolDetailed("list_allowed_directories", fs).toolClass).toBe("pure");
    const gh = { ...server, url: "https://api.githubcopilot.com/mcp/", command: undefined };
    expect(classifyToolDetailed("get_issue", gh).toolClass).toBe("source");
    expect(classifyToolDetailed("create_pull_request", gh).toolClass).toBe("sink");
    expect(classifyToolDetailed("delete_file", gh).capabilities).toContain("deletes_data");
    expect(classifyToolDetailed("brand_new_tool", gh).reasons).not.toContain("catalog:github");
  });

  it("lets annotations raise a catalog class but never lower it", () => {
    const fs = { ...server, command: "npx", args: ["@modelcontextprotocol/server-filesystem"] };
    expect(classifyToolDetailed("read_text_file", fs, { name: "read_text_file", inputSchema: {}, annotations: { destructiveHint: true } }).toolClass).toBe("sink");
    expect(classifyToolDetailed("write_file", fs, { name: "write_file", inputSchema: {}, annotations: { readOnlyHint: true } }).toolClass).toBe("sink");
  });

  it("honors a catalog override or opt out in config", () => {
    const custom = { ...server, command: "./my-fs-build", catalog: "filesystem" };
    expect(classifyToolDetailed("directory_tree", custom).reasons).toContain("catalog:filesystem");
    const off = { ...server, command: "npx", args: ["@modelcontextprotocol/server-filesystem"], catalog: false as const };
    expect(classifyToolDetailed("directory_tree", off).reasons).not.toContain("catalog:filesystem");
  });

  it("does not let an untrusted description make an unknown tool look like a source", () => {
    const tool = { name: "custom", description: "Read a file and list its lines", inputSchema: {} };
    expect(classifyToolDetailed("custom", server, tool).toolClass).toBe("unknown");
    expect(classifyToolDetailed("custom", { ...server, trust: "trusted" }, tool).toolClass).toBe("source");
    const sends = { name: "custom", description: "Sends an email to the address", inputSchema: {} };
    expect(classifyToolDetailed("custom", server, sends).toolClass).toBe("sink");
  });

  it("raises risk from input schema property names", () => {
    const schema = (properties: Record<string, unknown>) => ({ name: "do_it", inputSchema: { type: "object", properties } });
    expect(classifyToolDetailed("do_it", server, schema({ to: { type: "string" }, note: {} })).capabilities).toContain("sends_message");
    expect(classifyToolDetailed("do_it", server, schema({ cmd: {} })).toolClass).toBe("sink");
    expect(classifyToolDetailed("do_it", server, schema({ path: {}, content: {} })).capabilities).toContain("file_write");
    expect(classifyToolDetailed("do_it", server, schema({ options: { type: "object", properties: { webhook_url: {} } } })).toolClass).toBe("sink");
    expect(classifyToolDetailed("do_it", server, schema({ query: {} })).toolClass).toBe("unknown");
  });
});

