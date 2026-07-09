import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Command } from "commander";
import YAML from "yaml";
import { describe, expect, it } from "vitest";
import {
  inspectClientCoverage,
  installAllClientConfigs,
  installClientConfig,
  resolveClientConfigPath,
  selectInstallConfigPath,
  type InstallConfigResult
} from "../src/install-config.js";

describe("installClientConfig", () => {
  it("injects a wrapper entry while preserving existing config and creating a backup", async () => {
    const { root, clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const original = {
      theme: "dark",
      mcpServers: {
        existing: { command: "node", args: ["server.js"] }
      }
    };
    await writeFile(clientConfigPath, `${JSON.stringify(original, null, 2)}\n`, "utf8");

    try {
      const result = await installClientConfig({
        serverName: "filesystem",
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        cwd: root
      });

      const updated = JSON.parse(await readFile(clientConfigPath, "utf8")) as Record<string, unknown>;
      const mcpServers = updated.mcpServers as Record<string, { command: string; args: string[] }>;
      expect(updated.theme).toBe("dark");
      expect(mcpServers.existing).toEqual(original.mcpServers.existing);
      expect(mcpServers["palizade-filesystem"]).toEqual(result.entry);
      expect(result.entry.command).toBe(process.execPath);
      expect(result.entry.args).toEqual([cliPath, "wrap", "filesystem", "-c", palizadeConfigPath]);
      expect(isAbsolute(result.entry.args[0] ?? "")).toBe(true);
      expect(isAbsolute(result.entry.args[4] ?? "")).toBe(true);
      expect(result.backupPath).toBe(`${clientConfigPath}.bak`);
      expect(await readFile(`${clientConfigPath}.bak`, "utf8")).toBe(`${JSON.stringify(original, null, 2)}\n`);
    } finally {
      await cleanup();
    }
  });

  it("refuses malformed existing JSON without overwriting or backing up", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    await writeFile(clientConfigPath, "{ nope", "utf8");

    try {
      await expect(installClientConfig({
        serverName: "filesystem",
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath
      })).rejects.toThrow("Failed to parse Claude Desktop config");
      expect(await readFile(clientConfigPath, "utf8")).toBe("{ nope");
      await expect(stat(`${clientConfigPath}.bak`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await cleanup();
    }
  });

  it("requires force before overwriting an existing entry", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const existingEntry = { command: "old", args: ["old"] };
    await writeFile(clientConfigPath, JSON.stringify({
      mcpServers: {
        "palizade-filesystem": existingEntry
      }
    }, null, 2), "utf8");

    try {
      await expect(installClientConfig({
        serverName: "filesystem",
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath
      })).rejects.toThrow("Use --force to overwrite it");
      let current = JSON.parse(await readFile(clientConfigPath, "utf8")) as { mcpServers: Record<string, unknown> };
      expect(current.mcpServers["palizade-filesystem"]).toEqual(existingEntry);

      await installClientConfig({
        serverName: "filesystem",
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        force: true
      });
      const overwritten = JSON.parse(await readFile(clientConfigPath, "utf8")) as { mcpServers: Record<string, { args: string[] }> };
      expect(overwritten.mcpServers["palizade-filesystem"]?.args).toEqual([cliPath, "wrap", "filesystem", "-c", palizadeConfigPath]);
    } finally {
      await cleanup();
    }
  });

  it("prints the would-be config in dry-run mode without writing or backing up", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const original = `{"mcpServers":{}}\n`;
    await writeFile(clientConfigPath, original, "utf8");

    try {
      const result = await installClientConfig({
        serverName: "filesystem",
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        dryRun: true
      });

      expect(result.written).toBe(false);
      expect(result.configJson).toContain("\"palizade-filesystem\"");
      expect(await readFile(clientConfigPath, "utf8")).toBe(original);
      await expect(stat(`${clientConfigPath}.bak`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await cleanup();
    }
  });

  it("wraps every unprotected configured MCP server and adds upstream definitions to palizade.yaml", async () => {
    const { root, clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const fetchCwd = join(root, "servers", "fetch");
    const original = {
      mcpServers: {
        fetch: {
          command: "node",
          args: ["fetch-server.mjs"],
          cwd: fetchCwd,
          env: { FETCH_TOKEN: "test-token" }
        },
        github: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"]
        },
        already: {
          command: process.execPath,
          args: [cliPath, "wrap", "already", "-c", palizadeConfigPath]
        }
      }
    };
    await writeFile(clientConfigPath, `${JSON.stringify(original, null, 2)}\n`, "utf8");

    try {
      const result = await installAllClientConfigs({
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        cwd: root
      });

      expect(result.wrapped.map((server) => server.name)).toEqual(["fetch", "github"]);
      expect(result.skipped).toEqual([{ name: "already", reason: "already wrapped by Palizade" }]);
      expect(result.backupPath).toBe(`${clientConfigPath}.bak`);
      expect(result.lockCommands).toHaveLength(2);
      expect(result.lockCommands[0]).toContain("lock approve fetch");

      const updated = JSON.parse(await readFile(clientConfigPath, "utf8")) as { mcpServers: Record<string, { command: string; args: string[] }> };
      expect(updated.mcpServers.fetch).toEqual({
        command: process.execPath,
        args: [cliPath, "wrap", "fetch", "-c", palizadeConfigPath]
      });
      expect(updated.mcpServers.github).toEqual({
        command: process.execPath,
        args: [cliPath, "wrap", "github", "-c", palizadeConfigPath]
      });
      expect(updated.mcpServers.already).toEqual(original.mcpServers.already);

      const palizade = YAML.parse(await readFile(palizadeConfigPath, "utf8")) as {
        servers: Record<string, { command: string; args: string[]; cwd?: string; env?: Record<string, string>; trust: string; toolClasses: Record<string, string> }>;
      };
      expect(palizade.servers.fetch).toEqual({
        command: "node",
        args: ["fetch-server.mjs"],
        cwd: fetchCwd,
        env: { FETCH_TOKEN: "test-token" },
        trust: "untrusted",
        toolClasses: {}
      });
      expect(palizade.servers.github).toEqual({
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github"],
        trust: "untrusted",
        toolClasses: {}
      });
    } finally {
      await cleanup();
    }
  });

  it("is idempotent when install-config --all sees already wrapped entries", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    await writeFile(clientConfigPath, JSON.stringify({
      mcpServers: {
        fetch: { command: "node", args: ["fetch-server.mjs"] },
        github: { command: "node", args: ["github-server.mjs"] }
      }
    }, null, 2), "utf8");

    try {
      await installAllClientConfigs({ clientConfigPath, configPath: palizadeConfigPath, cliPath });
      const afterFirstRun = await readFile(clientConfigPath, "utf8");
      const result = await installAllClientConfigs({ clientConfigPath, configPath: palizadeConfigPath, cliPath });

      expect(result.wrapped).toEqual([]);
      expect(result.skipped.map((server) => server.name)).toEqual(["fetch", "github"]);
      expect(result.written).toBe(false);
      expect(await readFile(clientConfigPath, "utf8")).toBe(afterFirstRun);
    } finally {
      await cleanup();
    }
  });

  it("prints install-config --all dry-run output without writing client or Palizade config", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const originalClient = JSON.stringify({
      mcpServers: {
        fetch: { command: "node", args: ["fetch-server.mjs"] }
      }
    }, null, 2);
    const originalPalizade = "servers: {}\n";
    await writeFile(clientConfigPath, originalClient, "utf8");
    await writeFile(palizadeConfigPath, originalPalizade, "utf8");

    try {
      const result = await installAllClientConfigs({
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        dryRun: true
      });

      expect(result.written).toBe(false);
      expect(result.configJson).toContain("\"wrap\"");
      expect(result.palizadeConfigJson).toContain("trust: untrusted");
      expect(await readFile(clientConfigPath, "utf8")).toBe(originalClient);
      expect(await readFile(palizadeConfigPath, "utf8")).toBe(originalPalizade);
      await expect(stat(`${clientConfigPath}.bak`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await cleanup();
    }
  });

  it("enumerates servers from --client-config separately from palizade.yaml", async () => {
    const { root, clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const spawnCwd = join(root, "spawn-cwd");
    await mkdir(spawnCwd, { recursive: true });
    await writeFile(join(spawnCwd, "palizade.yaml"), "servers: {}\n", "utf8");
    await writeFile(clientConfigPath, JSON.stringify({
      mcpServers: {
        fetch: { command: "node", args: ["fetch-server.mjs"] }
      }
    }, null, 2), "utf8");
    await writeFile(palizadeConfigPath, "servers: {}\n", "utf8");

    try {
      const result = await installAllClientConfigs({
        clientConfigPath,
        configPath: palizadeConfigPath,
        cliPath,
        cwd: spawnCwd,
        dryRun: true
      });

      expect(result.clientConfigPath).toBe(clientConfigPath);
      expect(result.palizadeConfigPath).toBe(palizadeConfigPath);
      expect(result.wrapped.map((server) => server.name)).toEqual(["fetch"]);
      expect(result.configJson).toContain("\"fetch\"");
      expect(result.palizadeConfigJson).toContain("fetch:");
    } finally {
      await cleanup();
    }
  });

  it("reports client coverage for protected and unprotected MCP servers", async () => {
    const { clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    await writeFile(clientConfigPath, JSON.stringify({
      mcpServers: {
        unwrapped: { command: "node", args: ["server.mjs"] },
        wrapped: { command: process.execPath, args: [cliPath, "wrap", "wrapped", "-c", palizadeConfigPath] }
      }
    }, null, 2), "utf8");

    try {
      const coverage = await inspectClientCoverage({ clientConfigPath });

      expect(coverage.existed).toBe(true);
      expect(coverage.rows).toEqual([
        {
          name: "unwrapped",
          wrapped: false,
          command: "node",
          advice: "WARNING: unwrapped is configured but NOT protected by Palizade - run palizade install-config unwrapped"
        },
        {
          name: "wrapped",
          wrapped: true,
          command: process.execPath
        }
      ]);
      expect(coverage.warnings).toEqual([
        "WARNING: unwrapped is configured but NOT protected by Palizade - run palizade install-config unwrapped"
      ]);
    } finally {
      await cleanup();
    }
  });

  it("uses the install-config --config value for the emitted -c path when cwd differs", async () => {
    const { root, clientConfigPath, palizadeConfigPath, cliPath, cleanup } = await makeFixture();
    const spawnCwd = join(root, "spawn-cwd");
    await mkdir(spawnCwd, { recursive: true });

    try {
      const program = new Command();
      let result: InstallConfigResult | undefined;
      program
        .exitOverride()
        .option("-c, --config <path>", "Path to palizade.yaml", "palizade.yaml");
      program.command("install-config")
        .argument("<serverName>")
        .option("--config <path>", "Path to this project's palizade.yaml")
        .option("--dry-run", "Print without writing", false)
        .action(async (serverName: string, _options: { config?: string; dryRun: boolean }, command: Command) => {
          result = await installClientConfig({
            serverName,
            clientConfigPath,
            configPath: selectInstallConfigPath(command, program),
            cliPath,
            cwd: spawnCwd,
            dryRun: true
          });
        });

      await program.parseAsync(["node", "palizade", "install-config", "filesystem", "--config", palizadeConfigPath, "--dry-run"]);

      expect(result?.entry.args).toEqual([cliPath, "wrap", "filesystem", "-c", palizadeConfigPath]);
      expect(result?.warnings).toEqual([]);
    } finally {
      await cleanup();
    }
  });

  it("resolves the default Claude Desktop config location by platform", () => {
    expect(resolveClientConfigPath("claude-desktop", "win32", { APPDATA: "C:\\Users\\hunar\\AppData\\Roaming" }, "C:\\Users\\hunar"))
      .toBe("C:\\Users\\hunar\\AppData\\Roaming\\Claude\\claude_desktop_config.json");
    expect(resolveClientConfigPath("claude-desktop", "darwin", {}, "/Users/hunar"))
      .toBe("/Users/hunar/Library/Application Support/Claude/claude_desktop_config.json");
    expect(resolveClientConfigPath("claude-desktop", "linux", {}, "/home/hunar"))
      .toBe("/home/hunar/.config/Claude/claude_desktop_config.json");
  });
});

async function makeFixture(): Promise<{
  root: string;
  clientConfigPath: string;
  palizadeConfigPath: string;
  cliPath: string;
  cleanup: () => Promise<void>;
}> {
  const root = await mkdtemp(join(tmpdir(), "palizade-install-config-"));
  const clientConfigPath = join(root, "Claude", "claude_desktop_config.json");
  const palizadeConfigPath = join(root, "project", "palizade.yaml");
  const cliPath = join(root, "node_modules", "palizade", "dist", "index.cjs");
  await mkdir(join(root, "Claude"), { recursive: true });
  await mkdir(join(root, "project"), { recursive: true });
  await mkdir(join(root, "node_modules", "palizade", "dist"), { recursive: true });
  await writeFile(palizadeConfigPath, "servers: {}\n", "utf8");
  await writeFile(cliPath, "#!/usr/bin/env node\n", "utf8");
  return {
    root,
    clientConfigPath,
    palizadeConfigPath,
    cliPath,
    cleanup: () => rm(root, { recursive: true, force: true })
  };
}
