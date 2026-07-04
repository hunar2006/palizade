import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));
const bundlePath = join(packageDir, "dist", "index.cjs");
const packageJsonPath = join(packageDir, "package.json");

describe("bundled CLI version", () => {
  it.skipIf(!existsSync(bundlePath))("matches packages/cli/package.json", async () => {
    const pkg = JSON.parse(await readFile(packageJsonPath, "utf8")) as { version: string };
    const { stdout } = await execFileAsync(process.execPath, [bundlePath, "--version"], {
      cwd: packageDir,
      windowsHide: true
    });

    expect(stdout.trim()).toBe(pkg.version);
  });
});
