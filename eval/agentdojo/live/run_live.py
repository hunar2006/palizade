"""Run clean and attacked AgentDojo tasks on a local OpenAI compatible endpoint."""

import argparse
import hashlib
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import agentdojo.attacks  # noqa: F401  registers built in attacks in ATTACKS
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, PipelineConfig, SystemMessage, ToolsExecutionLoop
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.attacks.attack_registry import ATTACKS, load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites
from openai import OpenAI

from palizade_defense import Bridge, EpisodeTrace, PalizadeToolsExecutor
from score_live import report, score_attack_trace


VERSION = "v1.2.2"
PALIZADE_DEFENSES = {
    "palizade-default": ("default", "deny"),
    "palizade-default-approved": ("default", "approve"),
    "palizade-strict": ("strict", "deny"),
    "palizade-strict-approved": ("strict", "approve"),
}
APPROVAL_LABELS = {"deny": "denied", "approve": "granted"}
DEFENSES = ("none", "spotlighting_with_delimiting", "repeat_user_prompt", "tool_filter", *PALIZADE_DEFENSES)
FIXED_MODEL_NAME_ATTACKS = {
    "important_instructions_no_model_name",
    "important_instructions_no_names",
    "important_instructions_wrong_model_name",
}
ROOT = Path(__file__).resolve().parents[3]


class _AttackTargetPipeline(BasePipelineElement):
    """Minimal pipeline carrier so AgentDojo's load_attack resolves a valid MODEL_NAMES entry."""

    def __init__(self, name: str):
        self.name = name

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        raise NotImplementedError("Attack target carrier is only used during load_attack.")


class RecordingPipeline(BasePipelineElement):
    """Wraps a stock AgentDojo pipeline to capture environments and messages for trace scoring."""

    def __init__(self, pipeline: BasePipelineElement):
        self.pipeline = pipeline
        self.name = pipeline.name
        self.pre_environment = None
        self.post_environment = None
        self.last_messages = ()

    def query(self, query, runtime, env, messages=(), extra_args=None):
        if self.pre_environment is None:
            self.pre_environment = env.model_copy(deep=True)
        try:
            q, rt, post_env, msgs, extra = self.pipeline.query(query, runtime, env, messages, {} if extra_args is None else extra_args)
        except AbortAgentError as err:
            self.post_environment = err.task_environment
            self.last_messages = err.messages
            raise
        self.post_environment = post_env
        self.last_messages = msgs
        return q, rt, post_env, msgs, extra


class PalizadePipeline(AgentPipeline):
    def __init__(self, suite, llm, system_message, bridge, preset, approvals, name):
        self.suite = suite
        self.preset = preset
        self.approvals = approvals
        self.name = name
        self.executor = PalizadeToolsExecutor(bridge)
        self.trace = EpisodeTrace()
        self.pre_environment = None
        self.post_environment = None
        self.last_messages = ()
        super().__init__([SystemMessage(system_message), InitQuery(), llm, ToolsExecutionLoop([self.executor, llm])])

    def query(self, query, runtime, env, messages=(), extra_args=None):
        if self.pre_environment is None:
            self.pre_environment = env.model_copy(deep=True)
        functions = runtime.functions
        available = self.executor.start(self.suite, runtime, query, self.preset, approvals=self.approvals)
        runtime.update_functions({name: functions[name] for name in available})
        try:
            q, rt, post_env, msgs, extra = super().query(query, runtime, env, messages, {} if extra_args is None else extra_args)
            self.post_environment = post_env
            self.last_messages = msgs
            return q, rt, post_env, msgs, extra
        except AbortAgentError as err:
            self.post_environment = err.task_environment
            self.last_messages = err.messages
            raise
        finally:
            runtime.update_functions(functions)
            self.trace = self.executor.end()


def resolve_model_display_name(model: str, explicit: str | None) -> str:
    if explicit is not None:
        cleaned = explicit.strip()
        if not cleaned:
            raise ValueError("--model-display-name must not be empty.")
        return cleaned
    for key, display in MODEL_NAMES.items():
        if key in model:
            return display
    return MODEL_NAMES["local"]


def build_attack(attack_name: str, suite, model: str, display_name: str):
    """Load an AgentDojo attack via load_attack and apply the shared model display name."""
    lookup_key = next((key for key in MODEL_NAMES if key in model), "local")
    attack = load_attack(attack_name, suite, _AttackTargetPipeline(lookup_key))
    if hasattr(attack, "model_name") and attack_name not in FIXED_MODEL_NAME_ATTACKS:
        attack.model_name = display_name
    return attack


def dispatched_calls_from_messages(messages):
    """Return tool calls that AgentDojo's stock ToolsExecutor actually dispatched to the runtime."""
    calls = []
    for message in messages:
        if message["role"] != "tool":
            continue
        call = message["tool_call"]
        if call.function == EMPTY_FUNCTION_NAME:
            continue
        if message.get("error") == f"Invalid tool {call.function} provided.":
            continue
        calls.append(call)
    return calls


def comma_list(value):
    return list(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("PALIZADE_EVAL_BASE_URL") or os.getenv("OPENAI_BASE_URL"))
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-display-name", default=None)
    parser.add_argument("--defenses", type=comma_list, default="none,palizade-default")
    parser.add_argument("--suites", type=comma_list, default="workspace,slack,banking,travel")
    parser.add_argument("--user-tasks", type=comma_list)
    parser.add_argument("--injection-tasks", type=comma_list)
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--max-tasks", type=int)
    parser.add_argument("--logdir", type=Path, default=ROOT / ".palizade/agentdojo/live")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    url = urlsplit(args.base_url or "")
    if (url.scheme not in ("http", "https") or url.hostname not in ("localhost", "127.0.0.1", "::1")
            or url.username is not None or url.query or url.fragment):
        parser.error("Use a loopback base URL, such as http://127.0.0.1:11434/v1.")
    if not args.defenses or any(defense not in DEFENSES for defense in args.defenses):
        parser.error("Choose defenses from " + ", ".join(DEFENSES))
    available_attacks = ("none", *sorted(name for name in ATTACKS if name != "manual"))
    if args.attack not in available_attacks:
        parser.error("Choose --attack from " + ", ".join(available_attacks))
    if args.attack == "none" and args.injection_tasks is not None:
        parser.error("--injection-tasks requires an attack other than none.")
    try:
        display_name = resolve_model_display_name(args.model, args.model_display_name)
    except ValueError as error:
        parser.error(str(error))

    suites = get_suites(VERSION)
    if not args.suites or any(suite not in suites for suite in args.suites):
        parser.error("Choose suites from " + ", ".join(suites))
    if args.max_tasks is not None and args.max_tasks < 1:
        parser.error("--max-tasks must be positive.")

    tasks = [(name, suites[name], task) for name in args.suites for task in suites[name].user_tasks.values()
             if args.user_tasks is None or task.ID in args.user_tasks]
    if not tasks or (args.user_tasks and set(args.user_tasks) - {task.ID for _, _, task in tasks}):
        parser.error("One or more requested user tasks were not found in the selected suites.")
    tasks = tasks[:args.max_tasks]

    injection_map = {}
    if args.attack != "none":
        found_injections = set()
        for name in args.suites:
            selected = [task for task in suites[name].injection_tasks.values()
                        if args.injection_tasks is None or task.ID in args.injection_tasks]
            injection_map[name] = selected
            found_injections.update(task.ID for task in selected)
        if args.injection_tasks and set(args.injection_tasks) - found_injections:
            parser.error("One or more requested injection tasks were not found in the selected suites.")
        if not found_injections:
            parser.error("No injection tasks matched the selected suites.")

    return args, display_name, tasks, injection_map


def _write_checkpoint(path: Path, row: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(f".{uuid4().hex}.tmp")
    temp.write_text(json.dumps(row) + "\n", encoding="utf-8")
    temp.replace(path)


def _checkpoint_identity(args, display_name: str) -> str:
    harness = Path(__file__).resolve().parent
    inputs = [ROOT / "policies" / f"{preset}.yaml" for preset in ("default", "strict")]
    inputs.extend(harness.glob("*.py"))
    inputs.extend(path for path in harness.glob("*.mjs") if not path.name.endswith(".test.mjs"))
    for package in ("approvals", "audit", "core", "detectors", "policy", "taint"):
        inputs.extend((ROOT / "packages" / package / "dist").rglob("*.js"))
    digest = hashlib.sha256(json.dumps([VERSION, args.model, args.base_url, args.attack, display_name]).encode())
    for path in sorted(inputs):
        digest.update(json.dumps(path.relative_to(ROOT).as_posix()).encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()[:16]


def _palizade_metrics(pipeline: PalizadePipeline) -> dict:
    trace = pipeline.trace
    return {
        "proposed_calls": len(trace.proposed_calls),
        "executed_calls": len(trace.executed_calls),
        "blocked_calls": len(trace.blocked_calls),
        "approval_gated_calls": len(trace.approval_gated_calls),
        "approval_prompts": trace.approval_prompts,
    }


def _make_pipeline(defense, suite_name, llm, config, bridge):
    if defense in PALIZADE_DEFENSES:
        preset, approvals = PALIZADE_DEFENSES[defense]
        return PalizadePipeline(suite_name, llm, config.system_message, bridge, preset, approvals, f"{llm.name}-{defense}")
    return RecordingPipeline(AgentPipeline.from_config(config))


def run(argv=None, *, caption=None):
    args, display_name, tasks, injection_map = parse_args(argv)
    if caption is None:
        caption = (
            "This run contains clean tasks only. The attack columns have no episodes."
            if args.attack == "none"
            else f"Attack: {args.attack} (model display name: {display_name})."
        )
    logdir = args.logdir / _checkpoint_identity(args, display_name)
    if not args.resume and any(logdir.glob("episodes/*/*.jsonl")):
        raise SystemExit("Completed checkpoints exist. Pass --resume or choose a different log directory.")
    logdir.mkdir(parents=True, exist_ok=True)

    key = os.getenv("PALIZADE_EVAL_API_KEY") or os.getenv("OPENAI_API_KEY") or "local"
    completed_clean = skipped_clean = completed_attack = skipped_attack = 0

    attacks = {}
    if args.attack != "none":
        for suite_name, suite, _ in tasks:
            if suite_name not in attacks:
                attacks[suite_name] = build_attack(args.attack, suite, args.model, display_name)

    with ExitStack() as stack:
        http = stack.enter_context(httpx.Client(trust_env=False, follow_redirects=False, timeout=180))
        client = stack.enter_context(OpenAI(api_key=key, base_url=args.base_url, http_client=http, timeout=180))
        llm = OpenAILLM(client, args.model)
        llm.name = args.model
        bridge = stack.enter_context(Bridge()) if any(defense in PALIZADE_DEFENSES for defense in args.defenses) else None
        for defense in args.defenses:
            approvals_label = APPROVAL_LABELS[PALIZADE_DEFENSES[defense][1]] if defense in PALIZADE_DEFENSES else ""
            config = PipelineConfig(
                llm=llm,
                model_id=None,
                defense=None if defense in PALIZADE_DEFENSES or defense == "none" else defense,
                system_message_name=None,
                system_message=None,
            )
            for suite_name, suite, task in tasks:
                clean_path = logdir / "episodes" / defense / f"{suite_name}-{task.ID}.jsonl"
                if clean_path.exists():
                    skipped_clean += 1
                else:
                    pipeline = _make_pipeline(defense, suite_name, llm, config, bridge)
                    utility, _ = suite.run_task_with_pipeline(pipeline, task, injection_task=None, injections={})
                    row = {
                        "defense": defense,
                        "approvals": approvals_label,
                        "suite": suite_name,
                        "user_task": task.ID,
                        "injection_task": None,
                        "attack": None,
                        "utility": bool(utility),
                    }
                    if defense in PALIZADE_DEFENSES:
                        row.update(_palizade_metrics(pipeline))
                    _write_checkpoint(clean_path, row)
                    completed_clean += 1

                if args.attack == "none":
                    continue

                attack_obj = attacks[suite_name]
                suite_injections = injection_map[suite_name]
                if attack_obj.is_dos_attack:
                    suite_injections = suite_injections[:1]

                for injection_task in suite_injections:
                    try:
                        injections = attack_obj.attack(task, injection_task)
                    except ValueError as error:
                        if "not injectable" in str(error):
                            continue
                        raise
                    attack_path = logdir / "episodes" / defense / f"{suite_name}-{task.ID}-{args.attack}-{injection_task.ID}.jsonl"
                    if attack_path.exists():
                        skipped_attack += 1
                        continue
                    pipeline = _make_pipeline(defense, suite_name, llm, config, bridge)
                    utility, stock_security = suite.run_task_with_pipeline(
                        pipeline, task, injection_task=injection_task, injections=injections
                    )
                    if attack_obj.is_dos_attack:
                        attack_scores = {
                            "stock_attack_success": not bool(utility),
                            "executed_attack_success": not bool(utility),
                        }
                    else:
                        executed_calls = (
                            pipeline.trace.executed_calls
                            if defense in PALIZADE_DEFENSES
                            else dispatched_calls_from_messages(pipeline.last_messages)
                        )
                        attack_scores = score_attack_trace(
                            injection_task,
                            pipeline.last_messages,
                            pipeline.pre_environment,
                            pipeline.post_environment,
                            executed_calls,
                        )
                        attack_scores["stock_attack_success"] = bool(stock_security)
                    row = {
                        "defense": defense,
                        "approvals": approvals_label,
                        "suite": suite_name,
                        "user_task": task.ID,
                        "injection_task": injection_task.ID,
                        "attack": args.attack,
                        "model_display_name": display_name,
                        "utility": bool(utility),
                        **attack_scores,
                    }
                    if defense in PALIZADE_DEFENSES:
                        row.update(_palizade_metrics(pipeline))
                    _write_checkpoint(attack_path, row)
                    completed_attack += 1

    rows = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(logdir.glob("episodes/*/*.jsonl"))]
    report(rows, logdir, caption=caption)
    print(
        f"Completed {completed_clean} clean and {completed_attack} attack episodes. "
        f"Skipped {skipped_clean} clean and {skipped_attack} attack checkpoints."
    )
    print(f"Reports saved in {logdir}")
    return logdir


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        sys.exit(f"Evaluation failed ({type(error).__name__}). Check the model and local endpoint.")
