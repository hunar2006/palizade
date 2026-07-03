import { describe, expect, it } from "vitest";
import { classifyToolDetailed } from "./classifier.js";
import type { ServerConfig } from "./config.js";

describe("classifyToolDetailed", () => {
  const server: ServerConfig = {
    command: "node",
    args: [],
    env: {},
    trust: "semi",
    toolClasses: {},
    toolCapabilities: {},
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
});
