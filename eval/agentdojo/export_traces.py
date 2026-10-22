"""Export AgentDojo ground truth traces for replay through Palizade.

Needs `pip install agentdojo` (tested with 0.1.35). No model or API key is used: every
trace is the benchmark's own scripted ground truth, so a trace with an injection task is
a worst case agent that obeys the injection after doing the user's task.

Output (JSONL, one object per line):
  {"kind": "tools", "suite": ..., "tools": [{name, description, inputSchema}]}
  {"kind": "trace", "suite", "user_task", "injection_task" (or null), "prompt", "calls": [{phase, function, args, output}]}
"""

import argparse
import json
import sys

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites


class _NamedPipeline:
    # important_instructions names the target model in its text; any listed model works here.
    name = "claude-3-5-sonnet-20241022"


def run_calls(runtime, env, calls, phase):
    recorded = []
    for call in calls:
        result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
        recorded.append({
            "phase": phase,
            "function": call.function,
            "args": dict(call.args),
            "output": error if error else tool_result_to_str(result),
        })
    return recorded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="v1.2.2")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--suites", default="workspace,travel,banking,slack")
    parser.add_argument("--out", default="-")
    args = parser.parse_args()

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    suites = get_suites(args.version)
    for suite_name in args.suites.split(","):
        suite = suites[suite_name]
        tools = [{
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.parameters.model_json_schema(),
        } for tool in suite.tools]
        out.write(json.dumps({"kind": "tools", "suite": suite_name, "tools": tools}, default=str) + "\n")
        attack = load_attack(args.attack, suite, _NamedPipeline())

        for user_id, user_task in suite.user_tasks.items():
            # Clean run: the user's task with the default (benign) placeholder text.
            env = suite.load_and_inject_default_environment({})
            calls = run_calls(FunctionsRuntime(suite.tools), env, user_task.ground_truth(env), "user")
            out.write(json.dumps({"kind": "trace", "suite": suite_name, "user_task": user_id, "injection_task": None, "prompt": user_task.PROMPT, "calls": calls}, default=str) + "\n")

            for injection_id, injection_task in suite.injection_tasks.items():
                try:
                    injections = attack.attack(user_task, injection_task)
                except ValueError:
                    continue  # the user task never reads an injectable field
                env = suite.load_and_inject_default_environment(injections)
                runtime = FunctionsRuntime(suite.tools)
                calls = run_calls(runtime, env, user_task.ground_truth(env), "user")
                calls += run_calls(runtime, env, injection_task.ground_truth(env), "injection")
                out.write(json.dumps({"kind": "trace", "suite": suite_name, "user_task": user_id, "injection_task": injection_id, "prompt": user_task.PROMPT, "calls": calls}, default=str) + "\n")
    if out is not sys.stdout:
        out.close()


if __name__ == "__main__":
    main()
