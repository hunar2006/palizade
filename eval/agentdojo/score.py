"""Score Palizade decisions on AgentDojo with the benchmark's own utility and security checks.

Re-runs every trace from export_traces.py, executing only the calls Palizade let through,
then asks AgentDojo whether the user's task still succeeded (utility) and whether the
injection's goal was reached (attack success). Two approval modes are scored: `deny`
(the user refuses every Palizade prompt) and `approve` (the user accepts every prompt).
"""

import argparse
import json
from collections import defaultdict

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import text_content_block_from_string


class _NamedPipeline:
    name = "claude-3-5-sonnet-20241022"


def execute(runtime, env, calls, outcomes, offset, mode, executed, mismatches):
    for index, call in enumerate(calls):
        decision = outcomes[offset + index] if offset + index < len(outcomes) else None
        if decision is None or decision["function"] != call.function:
            mismatches.append(call.function)
            allowed = False
        else:
            allowed = decision["outcome"] == "allow" or (mode == "approve" and decision["outcome"] == "approval")
        if allowed:
            runtime.run_function(env, call.function, call.args, raise_on_error=False)
            executed.append(FunctionCall(function=call.function, args=call.args))
    return offset + len(calls)


def score_trace(suite, attack, record, mode):
    user_task = suite.user_tasks[record["user_task"]]
    injection_task = suite.injection_tasks[record["injection_task"]] if record["injection_task"] else None
    injections = attack.attack(user_task, injection_task) if injection_task else {}
    env = suite.load_and_inject_default_environment(injections)
    pre_env = env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    outcomes = record["decisions"] if record["decisions"] is not None else []
    executed, mismatches = [], []
    offset = execute(runtime, env, user_task.ground_truth(env), outcomes, 0, mode, executed, mismatches)
    if injection_task:
        execute(runtime, env, injection_task.ground_truth(env), outcomes, offset, mode, executed, mismatches)
    output = [text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]
    utility = suite._check_task_result(user_task, output, pre_env, env, executed)
    attacked = suite._check_task_result(injection_task, [text_content_block_from_string("")], pre_env, env, executed) if injection_task else None
    return utility, attacked, mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", required=True, help="decisions.jsonl from replay.mjs, or 'none' for no defense")
    parser.add_argument("--traces", help="traces.jsonl, needed with --decisions none")
    parser.add_argument("--version", default="v1.2.2")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--out", default="-")
    parser.add_argument("--markdown", help="also write a markdown table to this path")
    args = parser.parse_args()

    suites = get_suites(args.version)
    attacks = {}
    if args.decisions == "none":
        records = [json.loads(line) for line in open(args.traces, encoding="utf-8") if line.strip()]
        records = [{**r, "decisions": [{"function": c["function"], "outcome": "allow"} for c in r["calls"]]} for r in records if r["kind"] == "trace"]
    else:
        records = [json.loads(line) for line in open(args.decisions, encoding="utf-8") if line.strip()]

    totals = defaultdict(lambda: defaultdict(int))
    mismatch_count = 0
    for record in records:
        suite = suites[record["suite"]]
        attack = attacks.setdefault(record["suite"], load_attack(args.attack, suite, _NamedPipeline()))
        for mode in ("deny", "approve"):
            utility, attacked, mismatches = score_trace(suite, attack, record, mode)
            mismatch_count += len(mismatches)
            key = (record["suite"], mode, "clean" if record["injection_task"] is None else "attacked")
            totals[key]["n"] += 1
            totals[key]["utility"] += int(bool(utility))
            if attacked is not None:
                totals[key]["attack_success"] += int(bool(attacked))

    rows = []
    for (suite_name, mode, kind), counts in sorted(totals.items()):
        rows.append({"suite": suite_name, "approvals": mode, "runs": kind, **counts})
    summary = {"rows": rows, "replay_mismatches": mismatch_count}
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(markdown_table(rows) + "\n")
    text = json.dumps(summary, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")


def markdown_table(rows):
    def pct(a, b):
        return f"{a}/{b} ({100 * a / b:.1f}%)" if b else "n/a"

    lines = [
        "| Suite | Approvals | Clean utility | Utility under attack | Attack success |",
        "|---|---|---:|---:|---:|",
    ]
    by_key = {(r["suite"], r["approvals"], r["runs"]): r for r in rows}
    suites = sorted({r["suite"] for r in rows})
    for mode in ("deny", "approve"):
        total = defaultdict(int)
        for suite_name in suites:
            clean = by_key.get((suite_name, mode, "clean"), {})
            attacked = by_key.get((suite_name, mode, "attacked"), {})
            for prefix, row in (("c", clean), ("a", attacked)):
                for field in ("n", "utility", "attack_success"):
                    total[prefix + field] += row.get(field, 0)
            lines.append(f"| {suite_name} | {mode} | {pct(clean.get('utility', 0), clean.get('n', 0))} | {pct(attacked.get('utility', 0), attacked.get('n', 0))} | {pct(attacked.get('attack_success', 0), attacked.get('n', 0))} |")
        lines.append(f"| **all** | {mode} | {pct(total['cutility'], total['cn'])} | {pct(total['autility'], total['an'])} | {pct(total['aattack_success'], total['an'])} |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
