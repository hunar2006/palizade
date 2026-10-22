import { chmod, readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { build } from "esbuild";

const packageDir = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
const policyDir = join(packageDir, "../../policies");
const presets = Object.fromEntries(await Promise.all((await readdir(policyDir)).filter((name) => name.endsWith(".yaml")).map(async (name) => [name.slice(0, -5), await readFile(join(policyDir, name), "utf8")])));

// Inject package.json's version at bundle time so the single-file CJS build
// never relies on fragile runtime package.json path resolution.
await build({
  entryPoints: [join(packageDir, "src/index.ts")],
  bundle: true,
  platform: "node",
  format: "cjs",
  external: ["@huggingface/transformers"],
  outfile: join(packageDir, "dist/cli.cjs"),
  define: {
    __PKG_VERSION__: JSON.stringify(pkg.version),
    __POLICY_PRESETS__: JSON.stringify(presets)
  }
});

// A small launcher turns on Node's compile cache before loading the bundle, so repeated runs
// (one per hook call) skip most of the parse and compile work, and hides the SQLite
// ExperimentalWarning that node:sqlite prints on every start.
const launcher = `#!/usr/bin/env node
"use strict";
try { require("node:module").enableCompileCache?.(); } catch {}
const emitWarning = process.emitWarning;
process.emitWarning = function (warning, ...rest) {
  const type = typeof rest[0] === "string" ? rest[0] : rest[0]?.type ?? warning?.name;
  if (type === "ExperimentalWarning" && /SQLite/u.test(String(warning?.message ?? warning))) return;
  return emitWarning.call(process, warning, ...rest);
};
require("./cli.cjs");
`;
await writeFile(join(packageDir, "dist/index.cjs"), launcher, "utf8");
await chmod(join(packageDir, "dist/index.cjs"), 0o755);
