"""AgentDojo executor backed by a persistent Palizade policy process."""

import json
import subprocess
from ast import literal_eval
from dataclasses import dataclass, field
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string


class Bridge:
    def __enter__(self):
        self.process = subprocess.Popen(
            ["node", str(Path(__file__).with_name("bridge.mjs"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding="utf-8",
            bufsize=1,
        )
        return self

    def __exit__(self, *_):
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        finally:
            if self.process.stdout:
                self.process.stdout.close()

    def request(self, op, **fields):
        self.process.stdin.write(json.dumps({"op": op, **fields}, allow_nan=False) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("Palizade bridge exited before replying.")
        reply = json.loads(line)
        if not reply["ok"]:
            raise RuntimeError(reply["error"])
        return reply


@dataclass
class EpisodeTrace:
    proposed_calls: list[FunctionCall] = field(default_factory=list)
    executed_calls: list[FunctionCall] = field(default_factory=list)
    blocked_calls: list[FunctionCall] = field(default_factory=list)
    approval_gated_calls: list[FunctionCall] = field(default_factory=list)
    approval_prompts: int = 0
    withheld_results: int = 0


class PalizadeToolsExecutor(BasePipelineElement):
    def __init__(self, bridge: Bridge, formatter=tool_result_to_str):
        self.bridge = bridge
        self.formatter = formatter
        self.trace = None
        self.known_tools: set[str] = set()

    def start(self, suite: str, runtime: FunctionsRuntime, prompt: str, preset: str, approvals: str = "deny"):
        self.known_tools = set(runtime.functions.keys())
        tools = [
            {"name": tool.name, "description": tool.description, "inputSchema": tool.parameters.model_json_schema()}
            for tool in runtime.functions.values()
        ]
        reply = self.bridge.request("start", suite=suite, tools=tools, prompt=prompt, preset=preset, approvals=approvals)
        self.trace = EpisodeTrace()
        return reply["availableTools"]

    def end(self) -> EpisodeTrace:
        if self.trace is None:
            raise RuntimeError("Start a Palizade episode first.")
        self.trace.approval_prompts = self.bridge.request("end")["approvalPrompts"]
        trace, self.trace = self.trace, None
        self.known_tools = set()
        return trace

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        env = EmptyEnv() if env is None else env
        extra_args = {} if extra_args is None else extra_args
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        calls = messages[-1]["tool_calls"]
        if not calls:
            return query, runtime, env, messages, extra_args
        if self.trace is None:
            raise RuntimeError("Start a Palizade episode first.")

        results = [self._execute(runtime, env, call) for call in calls]
        return query, runtime, env, [*messages, *results], extra_args

    def _execute(self, runtime, env, call):
        self.trace.proposed_calls.append(call.model_copy(deep=True))
        if call.function == EMPTY_FUNCTION_NAME or call.function not in self.known_tools:
            return ChatToolResultMessage(
                role="tool", tool_call_id=call.id, tool_call=call,
                content=[text_content_block_from_string("")], error=f"Invalid tool {call.function} provided.",
            )
        # Inspect the same normalized list arguments that AgentDojo dispatches.
        args = {
            name: literal_eval(arg) if isinstance(arg, str) and is_string_list(arg) else arg
            for name, arg in call.model_dump(mode="json")["args"].items()
        }
        decision = self.bridge.request("check", name=call.function, arguments=args)
        result, error = "", None
        if decision["decision"] == "needs_approval":
            self.trace.approval_gated_calls.append(call.model_copy(deep=True))
            error = f"Palizade denied approval. {decision['reason']}"
        elif decision["decision"] == "block":
            if decision.get("approvalPrompted"):
                self.trace.approval_gated_calls.append(call.model_copy(deep=True))
            self.trace.blocked_calls.append(call.model_copy(deep=True))
            error = f"Palizade blocked the tool call. {decision['reason']}"
        elif decision["decision"] == "allow":
            if decision.get("approvalPrompted"):
                self.trace.approval_gated_calls.append(call.model_copy(deep=True))
            dispatched = call.model_copy(update={"args": decision["arguments"]}, deep=True)
            if dispatched.function in runtime.functions:
                self.trace.executed_calls.append(dispatched)
            raw_result, runtime_error = runtime.run_function(env, dispatched.function, dispatched.args)
            checked = self.bridge.request(
                "record", callId=decision["callId"],
                result=runtime_error if runtime_error is not None else self.formatter(raw_result),
                isError=runtime_error is not None,
            )
            if checked["blocked"]:
                self.trace.withheld_results += 1
                error = f"Palizade withheld the tool result. {checked['reason']}"
            elif runtime_error is not None:
                error = checked["result"]
            else:
                result = checked["result"]
        else:
            raise RuntimeError("Unexpected Palizade bridge decision.")

        return ChatToolResultMessage(
            role="tool", tool_call_id=call.id, tool_call=call,
            content=[text_content_block_from_string(result)], error=error,
        )
