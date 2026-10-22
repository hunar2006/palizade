#!/usr/bin/env node
// pnpm eval:agentdojo [--policies default,strict] [--out results/agentdojo]
// Needs a Python with `pip install agentdojo==0.1.35`; set PALIZADE_PYTHON to pick it.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const here = import.meta.dirname;
const { values } = parseArgs({
  options: {
    policies: { type: "string", default: "default,strict" },
    trust: { type: "string", default: "untrusted" },
    out: { type: "string", default: "results/agentdojo" },
    work: { type: "string", default: ".palizade/agentdojo" },
    refresh: { type: "boolean", default: false }
  }
});
const python = process.env.PALIZADE_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const out = resolve(values.out);
const work = resolve(values.work);
mkdirSync(out, { recursive: true });
mkdirSync(work, { recursive: true });

function run(command, args) {
  console.error(`$ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) {
    console.error(result.error ? String(result.error) : `exit ${result.status}`);
    process.exit(result.status ?? 1);
  }
}

const traces = join(work, "traces.jsonl");
if (values.refresh || !existsSync(traces)) {
  run(python, ["-I", join(here, "export_traces.py"), "--out", traces]);
}
run(python, ["-I", join(here, "score.py"), "--decisions", "none", "--traces", traces, "--out", join(out, "none.json"), "--markdown", join(out, "none.md")]);
for (const policy of values.policies.split(",")) {
  const decisions = join(work, `decisions-${policy}.jsonl`);
  run(process.execPath, [join(here, "replay.mjs"), "--traces", traces, "--out", decisions, "--policy", policy, "--trust", values.trust]);
  run(python, ["-I", join(here, "score.py"), "--decisions", decisions, "--out", join(out, `${policy}.json`), "--markdown", join(out, `${policy}.md`)]);
}
console.error(`results in ${out}`);
