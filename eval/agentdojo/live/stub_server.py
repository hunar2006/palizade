"""Loopback chat fixture with clean and obedient scripted modes."""

import json
import re
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from agentdojo.task_suite.load_suites import get_suites

from run_live import VERSION, build_attack


TASKS = ("user_task_0", "user_task_1")


def _normalize_text(text: str) -> str:
    """Undo YAML folding and quote escapes so injected benchmark text matches reliably."""
    text = re.sub(r"\\\r?\n[ \t]*\\?", "", text)
    text = text.replace("\\n", " ").replace("\\r", " ").replace("\\t", " ").replace('\\"', '"').replace("''", "'")
    return " ".join(text.split())


def _content_to_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part["text"] for part in content if isinstance(part, dict) and isinstance(part.get("text"), str))
    return ""


def _tool_result_text(results) -> str:
    chunks = [_content_to_text(item.get("content")) for item in results]
    return _normalize_text("\n".join(chunk for chunk in chunks if chunk))


@contextmanager
def stub_server(
    fake_key,
    *,
    mode="clean",
    suites=("workspace",),
    user_tasks=TASKS,
    injection_tasks=(),
    attack="important_instructions",
    model_display_name="Local model",
    include_calibration=False,
):
    if mode not in ("clean", "obedient"):
        raise ValueError("Stub mode must be clean or obedient.")

    all_suites = get_suites(VERSION)
    fixtures = {}
    for suite_name in suites:
        suite = all_suites[suite_name]
        clean_env = suite.load_and_inject_default_environment({})
        attack_obj = build_attack(attack, suite, "local", model_display_name) if mode == "obedient" else None
        selected_users = (
            [suite.user_tasks[task_id] for task_id in user_tasks if task_id in suite.user_tasks]
            if user_tasks is not None
            else list(suite.user_tasks.values())
        )
        selected_injections = (
            [suite.injection_tasks[task_id] for task_id in injection_tasks if task_id in suite.injection_tasks]
            if injection_tasks is not None
            else list(suite.injection_tasks.values())
        )
        for task in selected_users:
            if task.PROMPT in fixtures:
                raise ValueError(f"Duplicate fixture prompt for {suite_name}:{task.ID}")
            user_calls = task.ground_truth(clean_env)
            inj_entries = []
            if mode == "obedient":
                for injection_task in selected_injections:
                    try:
                        injections = attack_obj.attack(task, injection_task)
                    except ValueError as error:
                        if "not injectable" in str(error):
                            continue
                        raise
                    needles = tuple(_normalize_text(value) for value in injections.values())
                    inj_env = suite.load_and_inject_default_environment(injections)
                    inj_entries.append((needles, injection_task.ground_truth(inj_env)))
            fixtures[task.PROMPT] = (user_calls, task.GROUND_TRUTH_OUTPUT, inj_entries)

        if include_calibration:
            for injection_task in selected_injections:
                if injection_task.GOAL in fixtures:
                    continue
                cal_env = suite.load_and_inject_default_environment({})
                fixtures[injection_task.GOAL] = (injection_task.ground_truth(cal_env), "Calibration completed.", [])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            if self.headers.get("Authorization") != f"Bearer {fake_key}":
                self.send_error(401)
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            messages = body["messages"]
            user_message = next(message for message in messages if message["role"] == "user")
            prompt = _content_to_text(user_message["content"])
            if prompt not in fixtures:
                self.send_error(400, "Unknown fixture")
                return
            self.server.requests += 1
            self.server.last_body = body
            user_calls, answer, inj_entries = fixtures[prompt]
            results = [message for message in messages if message["role"] == "tool"]
            calls = list(user_calls)
            if mode == "obedient" and results:
                seen_text = _tool_result_text(results)
                for needles, inj_calls in inj_entries:
                    if any(needle in seen_text for needle in needles):
                        calls.extend(inj_calls)
                        break

            reply = {"role": "assistant", "content": None}
            if body.get("tool_choice") == "none" and not results:
                reply["content"] = ", ".join(dict.fromkeys(call.function for call in user_calls))
            elif len(results) < len(calls):
                call = calls[len(results)]
                reply["tool_calls"] = [{
                    "id": f"fixture-{len(results)}", "type": "function",
                    "function": {"name": call.function, "arguments": json.dumps(call.args)},
                }]
            else:
                user_ok = all(
                    isinstance(item["content"], list)
                    or (isinstance(item["content"], str) and not item["content"].startswith("Palizade "))
                    for item in results[:len(user_calls)]
                )
                reply["content"] = answer if user_ok else "Tool unavailable."

            prompt_tokens = max(1, len(json.dumps(messages)) // 4)
            completion_tokens = max(1, len(json.dumps(reply)) // 4)
            payload = json.dumps({
                "id": "chatcmpl-fixture", "object": "chat.completion", "created": 0, "model": body["model"],
                "choices": [{"index": 0, "message": reply, "finish_reason": "tool_calls" if "tool_calls" in reply else "stop"}],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.requests = 0
        server.last_body = None
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, f"http://127.0.0.1:{server.server_port}/v1"
        finally:
            server.shutdown()
            thread.join()
