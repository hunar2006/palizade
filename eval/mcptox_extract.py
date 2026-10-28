"""Turn MCPTox's recorded model responses into JSONL for eval/mcptox-replay.mjs.

usage: python -I eval/mcptox_extract.py <MCPTox-Benchmark folder> <out.jsonl>
Each line is one recorded tool call: the server's tools, the poisoned tool, the call the model
made, and MCPTox's own label for it. Nothing from the dataset is kept in this repository.
"""
import ast
import json
import re
import sys
import warnings

warnings.simplefilter("ignore", SyntaxWarning)


def parse_call(text):
    text = re.sub(r"<\|im_end\|>|<｜end▁of▁sentence｜>", "", text or "").strip()
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    for parse in (json.loads, ast.literal_eval):
        try:
            value = parse(match.group(0))
        except Exception:
            continue
        if isinstance(value, dict) and isinstance(value.get("tool"), str) and isinstance(value.get("arguments", {}), dict):
            return value
    return None


def parse_poisoned(text):
    name = re.search(r"^Tool:\s*(\S+)", text or "", re.M)
    return {"name": name.group(1) if name else "poisoned_tool", "description": text or ""}


def main():
    folder, out_path = sys.argv[1], sys.argv[2]
    data = json.load(open(f"{folder}/response_all.json", encoding="utf-8"))
    servers = data["servers"].values() if isinstance(data["servers"], dict) else data["servers"]
    written = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for server in servers:
            for index, instance in enumerate(server["malicious_instance"]):
                poisoned = parse_poisoned(instance.get("poisoned_tool"))
                for item in instance["datas"]:
                    for model, response in (item.get("response") or {}).items():
                        call = parse_call(response)
                        if call is None:
                            continue
                        out.write(json.dumps({
                            "server": server["server_name"],
                            "instance": f'{server["server_name"]}#{index}',
                            "tools": server["tool_names"],
                            "poisoned": poisoned,
                            "paradigm": (instance.get("metadata") or {}).get("paradigm"),
                            "risk": instance.get("security_risk_description"),
                            "model": model,
                            "label": (item.get("label") or {}).get(model),
                            "tool": call["tool"],
                            "arguments": call.get("arguments", {}),
                        }) + "\n")
                        written += 1
    print(f"wrote {written} calls", file=sys.stderr)


if __name__ == "__main__":
    main()
