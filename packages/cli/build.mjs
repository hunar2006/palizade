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

// The hook client is bundled on its own, with only node built ins, so a hook call can reach a
// running daemon without loading the main bundle.
await build({
  entryPoints: [join(packageDir, "src/hook-client.ts")],
  bundle: true,
  platform: "node",
  format: "cjs",
  outfile: join(packageDir, "dist/hook-client.cjs")
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
const argv = process.argv.slice(2);
if (argv.includes("hook") && !process.env.PALIZADE_NO_DAEMON) {
  // Try a running \`palizade daemon\`; on any failure run in process with the stdin already read.
  const preloaded = { chunks: [], ended: false };
  globalThis.__palizadeHookStdin = preloaded;
  let attempt;
  try { attempt = require("./hook-client.cjs").tryDaemon(argv, preloaded); } catch { attempt = Promise.resolve(false); }
  attempt.then((done) => { if (!done) require("./cli.cjs"); }, () => require("./cli.cjs"));
} else {
  require("./cli.cjs");
}
`;
await writeFile(join(packageDir, "dist/index.cjs"), launcher, "utf8");
await chmod(join(packageDir, "dist/index.cjs"), 0o755);
