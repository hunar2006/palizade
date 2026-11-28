"""Run clean, calibration, and attacked AgentDojo tasks on a local OpenAI compatible endpoint."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
import time
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
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
from agentdojo.attacks.attack_registry import ATTACKS, load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages
from agentdojo.types import get_text_content_as_str
from openai import BadRequestError, OpenAI, UnprocessableEntityError
from pydantic import ValidationError
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_random_exponential

from palizade_defense import Bridge, EpisodeTrace, PalizadeToolsExecutor
from score_live import report, score_attack_trace, score_user_utility


VERSION = "v1.2.2"
PALIZADE_DEFENSES = {
    "palizade-default": ("default", "deny"),
    "palizade-default-approved": ("default", "approve"),
    "palizade-strict": ("strict", "deny"),
    "palizade-strict-approved": ("strict", "approve"),
}
APPROVAL_LABELS = {"deny": "denied", "approve": "granted"}
DEFENSES = (
    "none",
    "spotlighting_with_delimiting",
    "repeat_user_prompt",
    "transformers_pi_detector",
    "tool_filter",
    *PALIZADE_DEFENSES,
)
FIXED_MODEL_NAME_ATTACKS = {
    "important_instructions_no_model_name",
    "important_instructions_no_names",
    "important_instructions_wrong_model_name",
}
ROOT = Path(__file__).resolve().parents[3]


def _plain_text_message_to_openai(message) -> dict:
    """Convert an AgentDojo message to standard OpenAI format with plain-string content."""
    role = message["role"]
    text = get_text_content_as_str(message["content"] or []) if message.get("content") is not None else None
    if role == "system":
        return {"role": "system", "content": text or ""}
    if role == "user":
        return {"role": "user", "content": text or ""}
    if role == "assistant":
        out = {"role": "assistant", "content": text}
        tool_calls = message.get("tool_calls")
        if tool_calls:
            out["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function, "arguments": json.dumps(tc.args)},
                }
                for tc in tool_calls
            ]
        return out
    if role == "tool":
        if message["tool_call_id"] is None:
            raise ValueError("`tool_call_id` should be specified for OpenAI.")
        content = message["error"] if message.get("error") else (text or "")
        return {
            "role": "tool",
            "tool_call_id": message["tool_call_id"],
            "name": message["tool_call"].function,
            "content": content,
        }
    raise ValueError(f"Invalid message role: {role}")


@retry(
    wait=wait_random_exponential(multiplier=1, max=40),
    stop=stop_after_attempt(3),
    reraise=True,
    retry=retry_if_not_exception_type((BadRequestError, UnprocessableEntityError)),
)
def _tracked_completion_request(client: OpenAI, kwargs: dict):
    return client.chat.completions.create(**kwargs)


class TrackedOpenAILLM(OpenAILLM):
    """OpenAILLM subclass that preserves temperature=0, sends seed/chat_template_kwargs, and counts tokens."""

    def __init__(
        self,
        client: OpenAI,
        model: str,
        reasoning_effort=None,
        temperature: float | None = 0.0,
        seed: int | None = None,
        disable_thinking: bool = False,
        system_role: str = "developer",
    ) -> None:
        super().__init__(client, model, reasoning_effort=reasoning_effort, temperature=temperature)
        self.seed = seed
        self.disable_thinking = disable_thinking
        self.system_role = system_role
        self.reset_usage()

    def reset_usage(self) -> None:
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._total_tokens = 0
        self._llm_calls = 0
        self._think_tag_leaked = False
        self._last_messages = []

    def snapshot_usage(self) -> dict:
        return {
            "prompt_tokens": self._prompt_tokens,
            "completion_tokens": self._completion_tokens,
            "total_tokens": self._total_tokens,
            "llm_calls": self._llm_calls,
            "think_tag_leaked": self._think_tag_leaked,
        }

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        if self.system_role == "system":
            openai_messages = [_plain_text_message_to_openai(message) for message in messages]
        else:
            openai_messages = [_message_to_openai(message, self.model) for message in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]

        kwargs = {"model": self.model, "messages": openai_messages}
        if openai_tools:
            kwargs["tools"] = openai_tools
            kwargs["tool_choice"] = "auto"
        # Fix AgentDojo's `temperature or NOT_GIVEN` bug that drops temperature=0.0.
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.seed is not None:
            kwargs["seed"] = self.seed
        if self.reasoning_effort is not None:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if self.disable_thinking:
            kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}

        self._last_messages = list(messages)
        completion = _tracked_completion_request(self.client, kwargs)
        self._llm_calls += 1
        usage = getattr(completion, "usage", None)
        if usage is not None:
            pt = int(getattr(usage, "prompt_tokens", 0) or 0)
            ct = int(getattr(usage, "completion_tokens", 0) or 0)
            tt = int(getattr(usage, "total_tokens", pt + ct) or (pt + ct))
            self._prompt_tokens += pt
            self._completion_tokens += ct
            self._total_tokens += tt

        raw_msg = completion.choices[0].message
        raw_content = getattr(raw_msg, "content", None) or ""
        if "<think>" in raw_content or "</think>" in raw_content:
            self._think_tag_leaked = True

        output = _openai_to_assistant_message(raw_msg)
        updated = [*messages, output]
        self._last_messages = updated
        return query, runtime, env, updated, extra_args


class _AttackTargetPipeline(BasePipelineElement):
    """Minimal pipeline carrier so AgentDojo's load_attack resolves a valid MODEL_NAMES entry."""

    def __init__(self, name: str):
        self.name = name

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        raise NotImplementedError("Attack target carrier is only used during load_attack.")


class RecordingPipeline(BasePipelineElement):
    """Wraps a stock AgentDojo pipeline to capture environments, retries, and partial traces on error."""

    def __init__(self, pipeline: BasePipelineElement, llm=None):
        self.pipeline = pipeline
        self.llm = llm
        self.name = pipeline.name
        self.pre_environment = None
        self.post_environment = None
        self.last_messages = ()
        self.attempts = 0
        self.cumulative_proposed_calls = []
        self.cumulative_dispatched_calls = []

    def query(self, query, runtime, env, messages=(), extra_args=None):
        if self.pre_environment is None and env is not None:
            self.pre_environment = env.model_copy(deep=True)
        if self.llm is not None and hasattr(self.llm, "_last_messages"):
            self.llm._last_messages = []
        attempt_messages = None
        completed = False
        try:
            q, rt, post_env, msgs, extra = self.pipeline.query(
                query, runtime, env, messages, {} if extra_args is None else extra_args
            )
            self.post_environment = post_env
            attempt_messages = msgs
            completed = True
            return q, rt, post_env, msgs, extra
        except AbortAgentError as err:
            self.post_environment = err.task_environment
            attempt_messages = err.messages
            completed = True
            raise
        finally:
            if not completed and env is not None:
                self.post_environment = env
            if attempt_messages is None:
                attempt_messages = tuple(getattr(self.llm, "_last_messages", ()) or ())
            self.last_messages = attempt_messages
            self.cumulative_proposed_calls.extend(functions_stack_trace_from_messages(attempt_messages))
            self.cumulative_dispatched_calls.extend(dispatched_calls_from_messages(attempt_messages))
            self.attempts += 1


class PalizadePipeline(AgentPipeline):
    def __init__(self, suite, llm, system_message, bridge, preset, approvals, name):
        self.suite = suite
        self.llm = llm
        self.preset = preset
        self.approvals = approvals
        self.name = name
        self.executor = PalizadeToolsExecutor(bridge)
        self.trace = EpisodeTrace()
        self.pre_environment = None
        self.post_environment = None
        self.last_messages = ()
        self.attempts = 0
        super().__init__([SystemMessage(system_message), InitQuery(), llm, ToolsExecutionLoop([self.executor, llm])])

    def query(self, query, runtime, env, messages=(), extra_args=None):
        if self.pre_environment is None and env is not None:
            self.pre_environment = env.model_copy(deep=True)
        if self.llm is not None and hasattr(self.llm, "_last_messages"):
            self.llm._last_messages = []
        functions = runtime.functions
        available = self.executor.start(self.suite, runtime, query, self.preset, approvals=self.approvals)
        runtime.update_functions({name: functions[name] for name in available})
        attempt_messages = None
        completed = False
        try:
            q, rt, post_env, msgs, extra = super().query(
                query, runtime, env, messages, {} if extra_args is None else extra_args
            )
            self.post_environment = post_env
            attempt_messages = msgs
            completed = True
            return q, rt, post_env, msgs, extra
        except AbortAgentError as err:
            self.post_environment = err.task_environment
            attempt_messages = err.messages
            completed = True
            raise
        finally:
            runtime.update_functions(functions)
            attempt_trace = self.executor.end()
            self.trace.proposed_calls.extend(attempt_trace.proposed_calls)
            self.trace.executed_calls.extend(attempt_trace.executed_calls)
            self.trace.blocked_calls.extend(attempt_trace.blocked_calls)
            self.trace.approval_gated_calls.extend(attempt_trace.approval_gated_calls)
            self.trace.approval_prompts += attempt_trace.approval_prompts
            self.trace.withheld_results += attempt_trace.withheld_results
            if not completed and env is not None:
                self.post_environment = env
            if attempt_messages is None:
                attempt_messages = tuple(getattr(self.llm, "_last_messages", ()) or ())
            self.last_messages = attempt_messages
            self.attempts += 1


def _build_shared_pi_detector():
    """Instantiate one reusable DeBERTa PI detector with 512-token truncation enabled."""
    from agentdojo.agent_pipeline.pi_detector import TransformersBasedPIDetector

    class _TruncatingTransformersPIDetector(TransformersBasedPIDetector):
        def detect(self, tool_output: str) -> tuple[bool, float]:
            result: dict = self.pipeline(tool_output, truncation=True, max_length=512)[0]  # type: ignore
            safety_score: float = result["score"] if result["label"] == self.safe_label else 1 - result["score"]
            is_injection: bool = safety_score < self.threshold
            return is_injection, safety_score

    return _TruncatingTransformersPIDetector(
        model_name="protectai/deberta-v3-base-prompt-injection-v2",
        safe_label="SAFE",
        threshold=0.5,
        mode="message",
    )


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


def _episode_key(row: dict) -> tuple:
    kind = row.get("episode_kind")
    if kind is None:
        if (
            "user_task" in row
            and row["user_task"] is None
            and row.get("injection_task") is not None
            and "stock_attack_success" not in row
        ):
            kind = "calibration"
        elif row.get("injection_task") is not None:
            kind = "attack"
        else:
            kind = "clean"
    return (
        row["defense"],
        kind,
        row["suite"],
        row.get("user_task"),
        row.get("injection_task"),
        row.get("attack"),
    )


def _load_existing_jsonl(path: Path) -> tuple[list[dict], set[tuple]]:
    rows = []
    keys = set()
    if not path.exists():
        return rows, keys
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError:
                print(
                    f"Warning: ignoring incomplete JSONL line {line_no} in {path} (likely from a prior disconnect).",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            rows.append(row)
            keys.add(_episode_key(row))
    return rows, keys


def _append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _format_eta(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "--"
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}h {minutes:02d}m"
    if minutes > 0:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("PALIZADE_EVAL_BASE_URL") or os.getenv("OPENAI_BASE_URL"))
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-display-name", default=None)
    parser.add_argument("--defenses", type=comma_list, default="none,palizade-default")
    parser.add_argument("--suites", type=comma_list, default=None)
    parser.add_argument("--user-tasks", type=comma_list)
    parser.add_argument("--injection-tasks", type=comma_list)
    parser.add_argument("--slice-file", type=Path, default=None)
    parser.add_argument("--include-calibration", action="store_true")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--max-tasks", type=int)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--disable-thinking", action="store_true")
    parser.add_argument("--system-role", choices=("developer", "system"), default="developer")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--vllm-version", default=None)
    parser.add_argument("--gpu-name", default=None)
    parser.add_argument("--repo-sha", default=None)
    parser.add_argument("--episodes-jsonl", type=Path, default=None)
    parser.add_argument("--logdir", type=Path, default=ROOT / ".palizade/agentdojo/live")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--quiet-progress", action="store_true")
    args = parser.parse_args(argv)

    url = urlsplit(args.base_url or "")
    if (
        url.scheme not in ("http", "https")
        or url.hostname not in ("localhost", "127.0.0.1", "::1")
        or url.username is not None
        or url.query
        or url.fragment
    ):
        parser.error("Use a loopback base URL, such as http://127.0.0.1:11434/v1.")
    if not args.defenses or any(defense not in DEFENSES for defense in args.defenses):
        parser.error("Choose defenses from " + ", ".join(DEFENSES))
    available_attacks = ("none", *sorted(name for name in ATTACKS if name != "manual"))
    if args.attack not in available_attacks:
        parser.error("Choose --attack from " + ", ".join(available_attacks))
    if args.attack == "none" and args.injection_tasks is not None and not args.include_calibration:
        parser.error("--injection-tasks requires an attack other than none or --include-calibration.")
    try:
        display_name = resolve_model_display_name(args.model, args.model_display_name)
    except ValueError as error:
        parser.error(str(error))

    suites = get_suites(VERSION)
    slice_spec = None
    if args.slice_file is not None:
        slice_spec = json.loads(args.slice_file.read_text(encoding="utf-8"))
        selected_suites = args.suites if args.suites is not None else list(slice_spec["suites"].keys())
    else:
        selected_suites = args.suites if args.suites is not None else ["workspace", "slack", "banking", "travel"]

    if not selected_suites or any(suite not in suites for suite in selected_suites):
        parser.error("Choose suites from " + ", ".join(suites))
    args.suites = selected_suites
    if args.max_tasks is not None and args.max_tasks < 1:
        parser.error("--max-tasks must be positive.")

    tasks = []
    for name in args.suites:
        suite = suites[name]
        if slice_spec is not None and args.user_tasks is None:
            allowed_users = slice_spec["suites"][name]["user_tasks"]
            for task_id in allowed_users:
                if task_id not in suite.user_tasks:
                    parser.error(f"Unknown user task {task_id} in slice file for suite {name}.")
                tasks.append((name, suite, suite.user_tasks[task_id]))
        else:
            for task in suite.user_tasks.values():
                if args.user_tasks is None or task.ID in args.user_tasks:
                    tasks.append((name, suite, task))

    if not tasks or (args.user_tasks and set(args.user_tasks) - {task.ID for _, _, task in tasks}):
        parser.error("One or more requested user tasks were not found in the selected suites.")
    tasks = tasks[:args.max_tasks]

    injection_map = {}
    if args.attack != "none" or args.include_calibration:
        found_injections = set()
        for name in args.suites:
            suite = suites[name]
            if slice_spec is not None and args.injection_tasks is None:
                allowed_injs = slice_spec["suites"][name]["injection_tasks"]
                selected = []
                for inj_id in allowed_injs:
                    if inj_id not in suite.injection_tasks:
                        parser.error(f"Unknown injection task {inj_id} in slice file for suite {name}.")
                    selected.append(suite.injection_tasks[inj_id])
            else:
                selected = [
                    task for task in suite.injection_tasks.values()
                    if args.injection_tasks is None or task.ID in args.injection_tasks
                ]
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
    identity_payload = [
        VERSION,
        args.model,
        args.base_url,
        args.attack,
        display_name,
        args.temperature,
        args.seed,
        args.disable_thinking,
        args.system_role,
    ]
    digest = hashlib.sha256(json.dumps(identity_payload).encode())
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
        "withheld_results": trace.withheld_results,
        "retries": max(0, pipeline.attempts - 1),
    }


def _non_palizade_call_metrics(pipeline: RecordingPipeline) -> dict:
    return {
        "proposed_calls": len(pipeline.cumulative_proposed_calls),
        "executed_calls": len(pipeline.cumulative_dispatched_calls),
        "retries": max(0, pipeline.attempts - 1),
    }


def _make_pipeline(defense, suite_name, llm, config, bridge, shared_pi_detector=None):
    if defense in PALIZADE_DEFENSES:
        preset, approvals = PALIZADE_DEFENSES[defense]
        return PalizadePipeline(suite_name, llm, config.system_message, bridge, preset, approvals, f"{llm.name}-{defense}")
    if defense == "transformers_pi_detector" and shared_pi_detector is not None:
        pipeline = AgentPipeline([
            SystemMessage(config.system_message),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(tool_result_to_str), shared_pi_detector, llm]),
        ])
        pipeline.name = f"{llm.name}-{defense}"
        return RecordingPipeline(pipeline, llm=llm)
    return RecordingPipeline(AgentPipeline.from_config(config), llm=llm)


def _is_recoverable_episode_error(error: Exception) -> str | None:
    if isinstance(error, BadRequestError):
        text = repr(error).lower()
        if (
            getattr(error, "code", None) == "context_length_exceeded"
            or getattr(error, "param", None) == "max_tokens"
            or "maximum context length" in text
            or "reduce the length of the messages" in text
            or "context_length_exceeded" in text
        ):
            return "context_length_exceeded"
    if isinstance(error, UnprocessableEntityError) and "max_new_tokens" in str(error):
        return "context_length_exceeded"
    if isinstance(error, json.JSONDecodeError):
        return "malformed_tool_call_json"
    if isinstance(error, ValidationError) and (
        getattr(error, "title", None) == "FunctionCall"
        and any(err.get("loc", (None,))[0] == "args" for err in error.errors())
    ):
        return "malformed_tool_call_args"
    return None


def _base_metadata(args, display_name: str) -> dict:
    meta = {
        "benchmark_version": VERSION,
        "model": args.model,
        "model_display_name": display_name,
        "temperature": args.temperature,
        "seed": args.seed,
        "thinking_disabled": bool(args.disable_thinking),
    }
    if args.run_id:
        meta["run_id"] = args.run_id
    if args.vllm_version:
        meta["vllm_version"] = args.vllm_version
    if args.gpu_name:
        meta["gpu_name"] = args.gpu_name
    if args.repo_sha:
        meta["repo_sha"] = args.repo_sha
    return meta


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
    if args.episodes_jsonl is not None and not args.resume and args.episodes_jsonl.exists() and args.episodes_jsonl.stat().st_size > 0:
        raise SystemExit("Existing --episodes-jsonl file is non-empty. Pass --resume or choose a new file.")
    logdir.mkdir(parents=True, exist_ok=True)

    existing_jsonl_rows, recorded_keys = (
        _load_existing_jsonl(args.episodes_jsonl) if args.episodes_jsonl is not None and args.resume else ([], set())
    )

    key = os.getenv("PALIZADE_EVAL_API_KEY") or os.getenv("OPENAI_API_KEY") or "local"
    completed_clean = skipped_clean = completed_cal = skipped_cal = completed_attack = skipped_attack = 0

    attacks = {}
    if args.attack != "none":
        for suite_name, suite, _ in tasks:
            if suite_name not in attacks:
                attacks[suite_name] = build_attack(args.attack, suite, args.model, display_name)

    # Precompute total planned episodes for progress reporting.
    suites_ordered = list(dict.fromkeys((suite_name, suite) for suite_name, suite, _ in tasks))
    attack_plan: dict[tuple[str, str], list[tuple[object, dict]]] = {}
    planned_per_defense = len(tasks)
    if args.include_calibration:
        planned_per_defense += sum(len(injection_map.get(name, [])) for name, _ in suites_ordered)
    if args.attack != "none":
        for suite_name, _, task in tasks:
            attack_obj = attacks[suite_name]
            suite_injections = injection_map[suite_name]
            if attack_obj.is_dos_attack:
                suite_injections = suite_injections[:1]
            pairs = []
            for injection_task in suite_injections:
                try:
                    injections = attack_obj.attack(task, injection_task)
                except ValueError as error:
                    if "not injectable" in str(error):
                        continue
                    raise
                pairs.append((injection_task, injections))
            attack_plan[(suite_name, task.ID)] = pairs
            planned_per_defense += len(pairs)

    total_planned = planned_per_defense * len(args.defenses)
    done_total = 0
    ran_this_session = 0
    session_wall = 0.0
    session_in_tokens = 0
    session_out_tokens = 0
    run_meta = _base_metadata(args, display_name)

    def emit_progress(defense_name: str, label: str, wall_s: float):
        nonlocal ran_this_session, session_wall
        ran_this_session += 1
        session_wall += wall_s
        avg_s = session_wall / ran_this_session
        remaining = max(total_planned - done_total, 0)
        eta = _format_eta(avg_s * remaining)
        if not args.quiet_progress:
            print(
                f"[{done_total:>{len(str(total_planned))}}/{total_planned}] {defense_name} | {label} | "
                f"{wall_s:.1f}s (avg {avg_s:.1f}s/ep) | ETA {eta} | "
                f"tokens {session_in_tokens:,} in / {session_out_tokens:,} out",
                flush=True,
            )

    def persist_episode(checkpoint_path: Path, row: dict):
        _write_checkpoint(checkpoint_path, row)
        if args.episodes_jsonl is not None:
            _append_jsonl(args.episodes_jsonl, row)
            recorded_keys.add(_episode_key(row))

    with ExitStack() as stack:
        http = stack.enter_context(httpx.Client(trust_env=False, follow_redirects=False, timeout=180))
        client = stack.enter_context(OpenAI(api_key=key, base_url=args.base_url, http_client=http, timeout=180))
        llm = TrackedOpenAILLM(
            client,
            args.model,
            temperature=args.temperature,
            seed=args.seed,
            disable_thinking=args.disable_thinking,
            system_role=args.system_role,
        )
        llm.name = args.model
        bridge = stack.enter_context(Bridge()) if any(defense in PALIZADE_DEFENSES for defense in args.defenses) else None

        for defense in args.defenses:
            shared_pi_detector = _build_shared_pi_detector() if defense == "transformers_pi_detector" else None
            try:
                approvals_label = APPROVAL_LABELS[PALIZADE_DEFENSES[defense][1]] if defense in PALIZADE_DEFENSES else ""
                config = PipelineConfig(
                    llm=llm,
                    model_id=None,
                    defense=None if defense in PALIZADE_DEFENSES or defense == "none" else defense,
                    system_message_name=None,
                    system_message=None,
                )

                # 1. Clean user tasks
                for suite_name, suite, task in tasks:
                    clean_path = logdir / "episodes" / defense / f"{suite_name}-{task.ID}.jsonl"
                    clean_key = (defense, "clean", suite_name, task.ID, None, None)
                    if clean_path.exists() or clean_key in recorded_keys:
                        skipped_clean += 1
                        done_total += 1
                    else:
                        pipeline = _make_pipeline(defense, suite_name, llm, config, bridge, shared_pi_detector)
                        llm.reset_usage()
                        t0 = time.perf_counter()
                        episode_error = None
                        try:
                            utility, _ = suite.run_task_with_pipeline(pipeline, task, injection_task=None, injections={})
                        except Exception as err:
                            episode_error = _is_recoverable_episode_error(err)
                            if episode_error is None:
                                raise
                            utility = False
                        wall_s = time.perf_counter() - t0
                        if not episode_error and pipeline.pre_environment is not None and pipeline.post_environment is not None:
                            executed_calls = (
                                pipeline.trace.executed_calls
                                if defense in PALIZADE_DEFENSES
                                else pipeline.cumulative_dispatched_calls
                            )
                            utility = score_user_utility(
                                task,
                                pipeline.last_messages,
                                pipeline.pre_environment,
                                pipeline.post_environment,
                                executed_calls,
                            )
                        usage = llm.snapshot_usage()
                        session_in_tokens += usage["prompt_tokens"]
                        session_out_tokens += usage["completion_tokens"]
                        row = {
                            **run_meta,
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            "episode_kind": "clean",
                            "defense": defense,
                            "approvals": approvals_label,
                            "suite": suite_name,
                            "user_task": task.ID,
                            "injection_task": None,
                            "attack": None,
                            "utility": bool(utility),
                            "wall_seconds": round(wall_s, 3),
                            **usage,
                        }
                        if episode_error:
                            row["error"] = episode_error
                        if defense in PALIZADE_DEFENSES:
                            row.update(_palizade_metrics(pipeline))
                        else:
                            row.update(_non_palizade_call_metrics(pipeline))
                        persist_episode(clean_path, row)
                        completed_clean += 1
                        done_total += 1
                        emit_progress(defense, f"clean {suite_name}:{task.ID}", wall_s)

                # 2. Calibration episodes (each injection task solved standalone, matching benchmark.py)
                if args.include_calibration:
                    for suite_name, suite in suites_ordered:
                        for injection_task in injection_map.get(suite_name, []):
                            cal_path = logdir / "episodes" / defense / f"{suite_name}-calibration-{injection_task.ID}.jsonl"
                            cal_key = (defense, "calibration", suite_name, None, injection_task.ID, None)
                            if cal_path.exists() or cal_key in recorded_keys:
                                skipped_cal += 1
                                done_total += 1
                                continue
                            pipeline = _make_pipeline(defense, suite_name, llm, config, bridge, shared_pi_detector)
                            llm.reset_usage()
                            t0 = time.perf_counter()
                            episode_error = None
                            try:
                                stock_cal_ok, _ = suite.run_task_with_pipeline(
                                    pipeline, injection_task, injection_task=None, injections={}
                                )
                            except Exception as err:
                                episode_error = _is_recoverable_episode_error(err)
                                if episode_error is None:
                                    raise
                                stock_cal_ok = False
                            wall_s = time.perf_counter() - t0
                            usage = llm.snapshot_usage()
                            session_in_tokens += usage["prompt_tokens"]
                            session_out_tokens += usage["completion_tokens"]
                            if episode_error or pipeline.pre_environment is None or pipeline.post_environment is None:
                                executed_cal_ok = False
                            else:
                                executed_calls = (
                                    pipeline.trace.executed_calls
                                    if defense in PALIZADE_DEFENSES
                                    else pipeline.cumulative_dispatched_calls
                                )
                                executed_cal_ok = score_attack_trace(
                                    injection_task,
                                    pipeline.last_messages,
                                    pipeline.pre_environment,
                                    pipeline.post_environment,
                                    executed_calls,
                                )["executed_attack_success"]
                            row = {
                                **run_meta,
                                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                                "episode_kind": "calibration",
                                "defense": defense,
                                "approvals": approvals_label,
                                "suite": suite_name,
                                "user_task": None,
                                "injection_task": injection_task.ID,
                                "attack": None,
                                "utility": bool(executed_cal_ok),
                                "stock_utility": bool(stock_cal_ok),
                                "wall_seconds": round(wall_s, 3),
                                **usage,
                            }
                            if episode_error:
                                row["error"] = episode_error
                            if defense in PALIZADE_DEFENSES:
                                row.update(_palizade_metrics(pipeline))
                            else:
                                row.update(_non_palizade_call_metrics(pipeline))
                            persist_episode(cal_path, row)
                            completed_cal += 1
                            done_total += 1
                            emit_progress(defense, f"cal {suite_name}:{injection_task.ID}", wall_s)

                # 3. Attacked episodes
                if args.attack == "none":
                    continue

                for suite_name, suite, task in tasks:
                    attack_obj = attacks[suite_name]
                    for injection_task, injections in attack_plan[(suite_name, task.ID)]:
                        attack_path = logdir / "episodes" / defense / f"{suite_name}-{task.ID}-{args.attack}-{injection_task.ID}.jsonl"
                        attack_key = (defense, "attack", suite_name, task.ID, injection_task.ID, args.attack)
                        if attack_path.exists() or attack_key in recorded_keys:
                            skipped_attack += 1
                            done_total += 1
                            continue
                        pipeline = _make_pipeline(defense, suite_name, llm, config, bridge, shared_pi_detector)
                        llm.reset_usage()
                        t0 = time.perf_counter()
                        episode_error = None
                        try:
                            utility, stock_security = suite.run_task_with_pipeline(
                                pipeline, task, injection_task=injection_task, injections=injections
                            )
                        except Exception as err:
                            episode_error = _is_recoverable_episode_error(err)
                            if episode_error is None:
                                raise
                            utility, stock_security = False, False
                        wall_s = time.perf_counter() - t0
                        usage = llm.snapshot_usage()
                        session_in_tokens += usage["prompt_tokens"]
                        session_out_tokens += usage["completion_tokens"]

                        executed_calls = (
                            pipeline.trace.executed_calls
                            if defense in PALIZADE_DEFENSES
                            else pipeline.cumulative_dispatched_calls
                        )
                        if not episode_error and pipeline.pre_environment is not None and pipeline.post_environment is not None:
                            utility = score_user_utility(
                                task,
                                pipeline.last_messages,
                                pipeline.pre_environment,
                                pipeline.post_environment,
                                executed_calls,
                            )

                        if attack_obj.is_dos_attack:
                            attack_scores = {
                                "stock_attack_success": not bool(utility),
                                "executed_attack_success": not bool(utility),
                            }
                        elif episode_error:
                            if pipeline.pre_environment is not None and pipeline.post_environment is not None:
                                partial_scores = score_attack_trace(
                                    injection_task,
                                    pipeline.last_messages,
                                    pipeline.pre_environment,
                                    pipeline.post_environment,
                                    executed_calls,
                                )
                                executed_succeeded = bool(partial_scores["executed_attack_success"])
                            else:
                                executed_succeeded = True
                            attack_scores = {
                                "stock_attack_success": True,
                                "executed_attack_success": executed_succeeded,
                            }
                        else:
                            attack_scores = score_attack_trace(
                                injection_task,
                                pipeline.last_messages,
                                pipeline.pre_environment,
                                pipeline.post_environment,
                                executed_calls,
                            )
                            attack_scores["stock_attack_success"] = bool(stock_security)

                        row = {
                            **run_meta,
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            "episode_kind": "attack",
                            "defense": defense,
                            "approvals": approvals_label,
                            "suite": suite_name,
                            "user_task": task.ID,
                            "injection_task": injection_task.ID,
                            "attack": args.attack,
                            "utility": bool(utility),
                            **attack_scores,
                            "wall_seconds": round(wall_s, 3),
                            **usage,
                        }
                        if episode_error:
                            row["error"] = episode_error
                        if defense in PALIZADE_DEFENSES:
                            row.update(_palizade_metrics(pipeline))
                        else:
                            row.update(_non_palizade_call_metrics(pipeline))
                        persist_episode(attack_path, row)
                        completed_attack += 1
                        done_total += 1
                        emit_progress(defense, f"{suite_name}:{task.ID}x{injection_task.ID}", wall_s)
            finally:
                if shared_pi_detector is not None:
                    del shared_pi_detector
                    try:
                        import torch
                        if torch.cuda.is_available():
                            torch.cuda.empty_cache()
                    except Exception:
                        pass

    if args.episodes_jsonl is not None and args.episodes_jsonl.exists():
        all_rows, _ = _load_existing_jsonl(args.episodes_jsonl)
        deduped = {}
        for item in all_rows:
            deduped[_episode_key(item)] = item
        rows = list(deduped.values())
    else:
        rows = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(logdir.glob("episodes/*/*.jsonl"))]

    report(rows, logdir, caption=caption)
    cal_msg = f", {completed_cal} calibration" if args.include_calibration or skipped_cal else ""
    cal_skip_msg = f", {skipped_cal} calibration" if args.include_calibration or skipped_cal else ""
    print(
        f"Completed {completed_clean} clean{cal_msg} and {completed_attack} attack episodes. "
        f"Skipped {skipped_clean} clean{cal_skip_msg} and {skipped_attack} attack checkpoints."
    )
    print(f"Reports saved in {logdir}")
    return logdir


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        sys.exit(f"Evaluation failed ({type(error).__name__}). Check the model and local endpoint.")
