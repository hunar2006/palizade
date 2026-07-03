import { rmSync } from "node:fs";

for (const path of [
  "packages/core/dist",
  "packages/taint/dist",
  "packages/policy/dist",
  "packages/detectors/dist",
  "packages/audit/dist",
  "packages/approvals/dist",
  "packages/cli/dist"
]) {
  rmSync(path, { recursive: true, force: true });
}
