import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";

it.each(["claude-code", "cursor", "codex"])("prints %s deny decisions and exits 2 for all closed-mode hook errors", async (client) => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-hook-cli-"));
  const config = join(dir, "palizade.yaml");
  const event = client === "cursor" ? "beforeShellExecution" : "PreToolUse";
  const run = (input: string) => spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "-c", config, "hook", client, event], { input, encoding: "utf8", timeout: 10000 });
  try {
    const check = (input: string) => {
      const result = run(input);
      expect(result.status, result.stderr).toBe(2);
      const output = JSON.parse(result.stdout);
      expect(client === "cursor" ? output.permission : output.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(result.stdout + result.stderr).not.toContain("PRIVATE_INPUT");
    };
    check("{}"); // Missing config.
    await writeFile(config, "servers: []\n");
    check("{}"); // Invalid config.
    await writeFile(config, "servers: {}\nhooks: { failMode: closed, maxInputBytes: 1024 }\n");
    check("PRIVATE_INPUT".repeat(200)); // Oversized stdin.
    check("{PRIVATE_INPUT"); // Invalid JSON.
    check('{"tool_name":"Bash","tool_input":{"command":"npm test"},"command":"npm test"}'); // Missing policy during evaluation.
    await writeFile(config, "servers: {}\nhooks: { failMode: open, maxInputBytes: 1024 }\n");
    const open = run("{PRIVATE_INPUT");
    expect(open.status).toBe(0);
    expect(open.stdout).toBe("");
  } finally { await rm(dir, { recursive: true, force: true }); }
}, 20000);
