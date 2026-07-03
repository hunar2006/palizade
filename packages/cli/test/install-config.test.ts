import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Command } from "commander";
import { describe, expect, it } from "vitest";
import { installClientConfig, resolveClientConfigPath, selectInstallConfigPath, type InstallConfigResult } from "../src/install-config.js";

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
