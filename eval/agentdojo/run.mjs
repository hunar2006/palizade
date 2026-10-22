#!/usr/bin/env node
// pnpm eval:agentdojo [--policies default,strict] [--out results/agentdojo]
// Needs a Python with `pip install agentdojo==0.1.35`; set PALIZADE_PYTHON to pick it.
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const here = import.meta.dirname;
const { values } = parseArgs({
  options: {
    policies: { type: "string", default: "default,strict" },
    trust: { type: "string", default: "untrusted" },
    "user-intent": { type: "string", default: "on" },
    out: { type: "string", default: "results/agentdojo" },
    work: { type: "string", default: ".palizade/agentdojo" },
    refresh: { type: "boolean", default: false },
    // Fail when attack success rises or clean utility falls versus the results in this folder.
    compare: { type: "string" }
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
  run(process.execPath, [join(here, "replay.mjs"), "--traces", traces, "--out", decisions, "--policy", policy, "--trust", values.trust, "--user-intent", values["user-intent"]]);
  run(python, ["-I", join(here, "score.py"), "--decisions", decisions, "--out", join(out, `${policy}.json`), "--markdown", join(out, `${policy}.md`)]);
}
console.error(`results in ${out}`);

const totals = (file) => {
  const rows = JSON.parse(readFileSync(file, "utf8")).rows.filter((row) => row.approvals === "deny");
  const sum = (kind, field) => rows.filter((row) => row.runs === kind).reduce((total, row) => total + (row[field] ?? 0), 0);
  return { cleanUtility: sum("clean", "utility"), attackSuccess: sum("attacked", "attack_success") };
};
let regressed = false;
for (const policy of values.policies.split(",")) {
  const now = totals(join(out, `${policy}.json`));
  const line = `${policy}: clean utility ${now.cleanUtility}, attack success ${now.attackSuccess} (approvals denied)`;
  if (values.compare) {
    const before = totals(join(resolve(values.compare), `${policy}.json`));
    const worse = now.attackSuccess > before.attackSuccess || now.cleanUtility < before.cleanUtility;
    regressed ||= worse;
    console.error(`${worse ? "REGRESSED" : "ok"} ${line}; reference ${before.cleanUtility} / ${before.attackSuccess}`);
  } else {
    console.error(line);
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### AgentDojo ${policy}\n\n${readFileSync(join(out, `${policy}.md`), "utf8")}\n`);
}
if (regressed) process.exitCode = 1;
