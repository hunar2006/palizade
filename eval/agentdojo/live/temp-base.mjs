import { realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { CRITICAL_PATHS } from "../../../packages/core/dist/index.js";
import { matchesPathGlob } from "../../../packages/policy/dist/index.js";

export async function benchmarkTempBase() {
  const logical = resolve(tmpdir());
  const canonical = await realpath(logical);
  if ([logical, canonical].some((base) =>
    CRITICAL_PATHS.some((pattern) => matchesPathGlob(join(base, "agentdojo-workspace"), pattern)))) {
    throw new Error("The AgentDojo temp directory is under a Palizade protected path. Set TEMP and TMP (or TMPDIR) to a directory outside protected paths.");
  }
  return canonical;
}
