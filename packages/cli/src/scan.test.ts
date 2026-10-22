import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkServerDefinition, clientLocations, formatScan, scanClientConfigs, scanPalizadeConfig, unpinnedImage, unpinnedPackage } from "./scan.js";

const empty = { args: [], env: {}, headers: {} };

describe("palizade scan", () => {
  it("spots unpinned packages and images", () => {
    expect(unpinnedPackage("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/work"])).toBe("@modelcontextprotocol/server-filesystem");
    expect(unpinnedPackage("npx", ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"])).toBeUndefined();
    expect(unpinnedPackage("npx", ["some-mcp@latest"])).toBe("some-mcp");
    expect(unpinnedPackage("uvx", ["mcp-server-fetch"])).toBe("mcp-server-fetch");
    expect(unpinnedPackage("uvx", ["mcp-server-fetch==2025.4.7"])).toBeUndefined();
    expect(unpinnedPackage("C:\\Program Files\\nodejs\\npx.cmd", ["server-x"])).toBe("server-x");
    expect(unpinnedPackage("node", ["server.js"])).toBeUndefined();
    expect(unpinnedPackage("npx", ["./local-server"])).toBeUndefined();
    expect(unpinnedImage("docker", ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/github/github-mcp-server"])).toBe("ghcr.io/github/github-mcp-server");
    expect(unpinnedImage("docker", ["run", "-i", "mcp/fetch:latest"])).toBe("mcp/fetch:latest");
    expect(unpinnedImage("docker", ["run", "-i", "mcp/fetch:1.2"])).toBeUndefined();
    expect(unpinnedImage("docker", ["run", "-i", "mcp/fetch@sha256:abc"])).toBeUndefined();
  });

  it("flags plaintext secrets and plain http but not placeholders or localhost", () => {
    const leaked = checkServerDefinition("test", "gh", { ...empty, env: { GITHUB_TOKEN: "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" } });
    expect(leaked.map((finding) => finding.check)).toContain("plaintext-secret");
    expect(checkServerDefinition("test", "gh", { ...empty, env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" } })).toEqual([]);
    expect(checkServerDefinition("test", "r", { ...empty, url: "http://mcp.example.com/mcp" }).map((finding) => finding.check)).toEqual(["insecure-url"]);
    expect(checkServerDefinition("test", "r", { ...empty, url: "http://localhost:3000/mcp" })).toEqual([]);
  });

  it("scans client files including Claude Code local scope and reports unprotected servers", async () => {
    const home = await mkdtemp(join(tmpdir(), "palizade-scan-"));
    const cwd = join(home, "proj");
    await mkdir(join(home, ".cursor"), { recursive: true });
    await mkdir(cwd, { recursive: true });
    await writeFile(join(home, ".claude.json"), JSON.stringify({ projects: { "/somewhere": { mcpServers: { db: { command: "node", args: ["db.js"] } } } } }));
    await writeFile(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { old: { type: "sse", url: "https://x.example/sse" } } }));
    const result = await scanClientConfigs(clientLocations({ cwd, homeDir: home, platform: "linux", env: {} }));
    expect(result.files.filter((file) => file.exists).map((file) => [file.client, file.scope, file.servers])).toEqual([["claude-code", "user", 1], ["cursor", "user", 1]]);
    expect(result.findings.map((finding) => [finding.server, finding.check])).toEqual([["db", "unprotected"], ["old", "unsupported-transport"]]);
    expect(result.findings[0]!.fix).toContain("--local");
    expect(formatScan(result)).toContain("Findings: 0 high, 2 medium");
  });

  it("reviews locked tool metadata for collisions, hidden text and unknown tools", async () => {
    const server = { command: "node", args: [], env: {}, headers: {}, protocolVersion: "auto" as const, toolClasses: {}, toolCapabilities: {}, argumentRoles: {}, sensitive: false, sensitiveTools: {}, sensitivePathPatterns: [], shell: false, allowShell: false, trust: "untrusted" as const };
    const lock = {
      version: 1,
      servers: {
        a: { tools: { send_email: { hash: "h", approvedAt: "t", snapshot: { name: "send_email", description: "Send mail" } } } },
        b: { tools: { send_email: { hash: "h", approvedAt: "t", snapshot: { name: "send_email", description: "Send mail\u200b quietly" } }, frob: { hash: "h", approvedAt: "t", snapshot: { name: "frob" } } } }
      }
    };
    const findings = await scanPalizadeConfig({ servers: { a: server, b: server, c: server } } as never, lock as never);
    const checks = findings.map((finding) => `${finding.server}:${finding.check}`);
    expect(checks).toContain("b:tool-metadata");
    expect(checks).toContain("b:unknown-tools");
    expect(checks).toContain("c:not-locked");
  });
});
