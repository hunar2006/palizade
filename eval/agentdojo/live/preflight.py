"""Verify structured tool calling works reliably on 3 sample AgentDojo tasks before running the pilot."""

import argparse
import json
import os
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages
from agentdojo.types import get_text_content_as_str
from openai import OpenAI

from run_live import RecordingPipeline, TrackedOpenAILLM, VERSION, dispatched_calls_from_messages


DEFAULT_SLICE = Path(__file__).with_name("pilot_slice.json")
RAW_TOOL_CALL_MARKERS = ("<tool_call>", "</tool_call>", "\"tool_calls\"")


def _check_raw_tool_leak(messages) -> bool:
    for message in messages:
        if message["role"] != "assistant":
            continue
        text = get_text_content_as_str(message["content"] or []) if message["content"] else ""
        if any(marker in text for marker in RAW_TOOL_CALL_MARKERS):
            return True
    return False


def _check_think_leak(messages) -> bool:
    for message in messages:
        if message["role"] != "assistant":
            continue
        text = get_text_content_as_str(message["content"] or []) if message["content"] else ""
        if "<think>" in text or "</think>" in text:
            return True
    return False


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("PALIZADE_EVAL_BASE_URL") or os.getenv("OPENAI_BASE_URL"))
    parser.add_argument("--model", required=True)
    parser.add_argument("--slice-file", type=Path, default=DEFAULT_SLICE)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--disable-thinking", action="store_true")
    parser.add_argument("--system-role", choices=("developer", "system"), default="system")
    parser.add_argument("--require-usage", action="store_true")
    args = parser.parse_args(argv)
    url = urlsplit(args.base_url or "")
    if (
        url.scheme not in ("http", "https")
        or url.hostname not in ("localhost", "127.0.0.1", "::1")
        or url.username is not None
        or url.query
        or url.fragment
    ):
        parser.error("Use a loopback base URL, such as http://127.0.0.1:8000/v1.")
    return args


def run_preflight(argv=None) -> list[dict]:
    args = parse_args(argv)
    slice_data = json.loads(args.slice_file.read_text(encoding="utf-8"))
    preflight_tasks = slice_data.get("preflight_tasks", [])
    if len(preflight_tasks) != 3:
        raise SystemExit(f"Expected 3 preflight_tasks in {args.slice_file}, found {len(preflight_tasks)}.")

    suites = get_suites(VERSION)
    key = os.getenv("PALIZADE_EVAL_API_KEY") or os.getenv("OPENAI_API_KEY") or "local"
    results = []
    failures = []

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
        config = PipelineConfig(
            llm=llm,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
        )

        for entry in preflight_tasks:
            suite_name = entry["suite"]
            task_id = entry["user_task"]
            suite = suites[suite_name]
            task = suite.user_tasks[task_id]
            pipeline = RecordingPipeline(AgentPipeline.from_config(config))
            llm.reset_usage()
            t0 = time.perf_counter()
            error_text = None
            utility = False
            try:
                utility, _ = suite.run_task_with_pipeline(pipeline, task, injection_task=None, injections={})
            except Exception as err:
                error_text = f"{type(err).__name__}: {err}"
            elapsed = time.perf_counter() - t0
            usage = llm.snapshot_usage()
            messages = pipeline.last_messages
            proposed = functions_stack_trace_from_messages(messages)
            dispatched = dispatched_calls_from_messages(messages)
            valid_tool_names = set(tool.name for tool in suite.tools)
            invalid_names = [call.function for call in proposed if call.function not in valid_tool_names]
            non_dict_args = [call.function for call in proposed if not isinstance(call.args, dict)]
            raw_tool_leak = _check_raw_tool_leak(messages)
            think_leak = args.disable_thinking and (_check_think_leak(messages) or usage["think_tag_leaked"])
            final_output = model_output_from_messages(messages)

            task_failures = []
            if error_text:
                task_failures.append(f"exception ({error_text})")
            if len(proposed) == 0:
                task_failures.append("zero structured tool_calls emitted")
            if len(dispatched) == 0:
                task_failures.append("zero valid tool calls dispatched")
            if invalid_names:
                task_failures.append(f"unknown tool names: {invalid_names}")
            if non_dict_args:
                task_failures.append(f"non-dict tool arguments on: {non_dict_args}")
            if raw_tool_leak:
                task_failures.append("raw <tool_call> text leaked into assistant content (check --tool-call-parser)")
            if think_leak:
                task_failures.append("<think> tags leaked into assistant content despite --disable-thinking")
            if final_output is None:
                task_failures.append("missing final assistant message")
            if args.require_usage and (usage["prompt_tokens"] <= 0 or usage["completion_tokens"] <= 0):
                task_failures.append("endpoint did not report prompt/completion token usage")

            row = {
                "suite": suite_name,
                "user_task": task_id,
                "ok": len(task_failures) == 0,
                "utility": bool(utility),
                "proposed_calls": len(proposed),
                "executed_calls": len(dispatched),
                "llm_calls": usage["llm_calls"],
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "wall_seconds": round(elapsed, 2),
                "issues": task_failures,
            }
            results.append(row)
            status = "PASS" if row["ok"] else "FAIL"
            print(
                f"[preflight {status}] {suite_name}:{task_id} | "
                f"calls={row['proposed_calls']}/{row['executed_calls']} | "
                f"utility={row['utility']} | "
                f"tokens={row['prompt_tokens']}in/{row['completion_tokens']}out | "
                f"{row['wall_seconds']}s"
                + (f" | issues={'; '.join(task_failures)}" if task_failures else ""),
                flush=True,
            )
            if task_failures:
                failures.append((f"{suite_name}:{task_id}", task_failures))

    if failures:
        lines = ["Tool-calling preflight FAILED. Stopping before pilot run:"]
        for label, issues in failures:
            lines.append(f"  - {label}: {'; '.join(issues)}")
        lines.append("Check vLLM --enable-auto-tool-choice, --tool-call-parser, and --default-chat-template-kwargs.")
        raise SystemExit("\n".join(lines))

    print("Tool-calling preflight PASSED on all 3 sample tasks.", flush=True)
    return results


if __name__ == "__main__":
    run_preflight()
