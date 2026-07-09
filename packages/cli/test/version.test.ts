import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
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

describe("bundled CLI config errors", () => {
  it.skipIf(!existsSync(bundlePath))("doctor reports a helpful message when palizade.yaml is missing", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "palizade-missing-config-"));
    try {
      const error = await execFileAsync(process.execPath, [bundlePath, "doctor"], {
        cwd,
        windowsHide: true
      }).then(
        () => undefined,
        (caught: unknown) => caught as { stderr?: string; stdout?: string; code?: number }
      );

      expect(error?.code).toBe(1);
      expect(error?.stderr ?? "").toContain("No palizade.yaml found in current directory. Run 'palizade init' first, or pass -c <path>.");
      expect(error?.stderr ?? "").not.toContain("ENOENT");
      expect(error?.stderr ?? "").not.toContain("no such file or directory");
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});
