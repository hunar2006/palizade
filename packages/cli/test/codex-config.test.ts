import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "smol-toml";
import YAML from "yaml";
import { describe, expect, it } from "vitest";
import { codexToClientEntry, removeServerTables } from "../src/codex-config.js";
import { installAllClientConfigs, resolveClientConfigPath } from "../src/install-config.js";

const CONFIG = `# my codex settings
model = "o4"

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env_vars = ["GITHUB_TOKEN"]
tool_timeout_sec = 45

[mcp_servers.github.env]
LOG = "debug"

[mcp_servers.github.tools.create_issue]
approval_mode = "prompt"

# remote with a token
[mcp_servers.linear]
url = "https://mcp.linear.example/mcp"
bearer_token_env_var = "LINEAR_TOKEN"
http_headers = { "X-Team" = "eng" }

[mcp_servers.figma]
url = "https://mcp.figma.example/mcp"

[profiles.fast]
model = "o4-mini"
`;

describe("Codex config", () => {
  it("resolves user, CODEX_HOME and project paths", () => {
    expect(resolveClientConfigPath("codex", "linux", {}, "/home/h")).toBe("/home/h/.codex/config.toml");
    expect(resolveClientConfigPath("codex", "linux", { CODEX_HOME: "/opt/codex" }, "/home/h")).toBe("/opt/codex/config.toml");
    expect(resolveClientConfigPath("codex", "linux", {}, "/home/h", "/work/app")).toBe("/work/app/.codex/config.toml");
  });

  it("maps remote credentials to placeholder headers", () => {
    expect(codexToClientEntry({ url: "https://x/mcp", bearer_token_env_var: "TOKEN", env_http_headers: { "X-Org": "ORG_ID" } }))
      .toEqual({ type: "http", url: "https://x/mcp", headers: { "X-Org": "${ORG_ID}", Authorization: "Bearer ${TOKEN}" } });
  });

  it("removes a server's tables and refuses inline definitions", () => {
    const removed = removeServerTables(CONFIG, "github")!;
    expect(removed).not.toContain("server-github");
    expect(removed).not.toContain("approval_mode");
    expect(removed).toContain("[profiles.fast]");
    expect(removeServerTables('mcp_servers = { inline = { command = "x" } }\n', "inline")).toBeUndefined();
  });

  it("wraps servers in place, keeps comments, settings and forwarded variables, and skips OAuth remotes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-codex-"));
    const clientConfigPath = join(dir, "config.toml");
    const palizadeConfigPath = join(dir, "palizade.yaml");
    const cliPath = join(dir, "index.cjs");
    await writeFile(clientConfigPath, CONFIG, "utf8");
    await writeFile(palizadeConfigPath, "servers: {}\n", "utf8");
    await writeFile(cliPath, "", "utf8");

    const result = await installAllClientConfigs({ client: "codex", clientConfigPath, configPath: palizadeConfigPath, cliPath, cwd: dir });

    expect(result.wrapped.map((server) => server.name)).toEqual(["github", "linear"]);
    expect(result.skipped.map((server) => server.name)).toEqual(["figma"]);
    const text = await readFile(clientConfigPath, "utf8");
    expect(text).toContain("# my codex settings");
    expect(text).toContain("# remote with a token");
    const toml = parse(text) as { model: string; profiles: unknown; mcp_servers: Record<string, Record<string, unknown>> };
    expect(toml.model).toBe("o4");
    expect(toml.profiles).toEqual({ fast: { model: "o4-mini" } });
    expect(toml.mcp_servers.github).toMatchObject({ args: [cliPath, "wrap", "github", "-c", palizadeConfigPath], tool_timeout_sec: 45, env_vars: ["GITHUB_TOKEN"], tools: { create_issue: { approval_mode: "prompt" } } });
    expect(toml.mcp_servers.github!.env).toBeUndefined();
    expect(toml.mcp_servers.linear).toMatchObject({ env_vars: ["LINEAR_TOKEN"] });
    expect(toml.mcp_servers.linear!.url).toBeUndefined();
    expect(toml.mcp_servers.figma).toEqual({ url: "https://mcp.figma.example/mcp" });
    const servers = (YAML.parse(await readFile(palizadeConfigPath, "utf8")) as { servers: Record<string, Record<string, unknown>> }).servers;
    expect(servers.github).toMatchObject({ command: "npx", env: { LOG: "debug" } });
    expect(servers.linear).toMatchObject({ url: "https://mcp.linear.example/mcp", headers: { "X-Team": "eng", Authorization: "Bearer ${LINEAR_TOKEN}" } });

    const again = await installAllClientConfigs({ client: "codex", clientConfigPath, configPath: palizadeConfigPath, cliPath, cwd: dir, dryRun: true });
    expect(again.wrapped).toEqual([]);
  });
});
