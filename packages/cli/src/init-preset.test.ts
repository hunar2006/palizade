import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import YAML from "yaml";

it.each(["default", "coding-agent", "research-readonly", "strict"])("initializes the current %s preset", async (preset) => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-init-"));
  try {
    execFileSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "init", "--preset", preset, "--output-dir", "output"], { cwd: dir, windowsHide: true });
    const config = YAML.parse(await readFile(join(dir, "palizade.yaml"), "utf8"));
    expect(config.policy).toBe(`policies/${preset}.yaml`);
    expect(config.protectedTargets.outputDirectory).toBe("output");
    expect(await readFile(join(dir, config.policy), "utf8")).toBe(await readFile(resolve(`policies/${preset}.yaml`), "utf8"));
    if (preset === "strict") expect(config.egress.mode).toBe("allowlist_only");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
