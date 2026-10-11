import { readFile, readdir } from "node:fs/promises";
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
  outfile: join(packageDir, "dist/index.cjs"),
  define: {
    __PKG_VERSION__: JSON.stringify(pkg.version),
    __POLICY_PRESETS__: JSON.stringify(presets)
  }
});
