"""Turn MCPTox's recorded model responses into JSONL for eval/mcptox-replay.mjs.

usage: python -I eval/mcptox_extract.py <MCPTox-Benchmark folder> <out.jsonl>
Each line is one recorded tool call: the server's tools (names, and the descriptions and argument
names from the clean system prompt), the poisoned tool, the call the model made, and MCPTox's own
label for it. Nothing from the dataset is kept in this repository.
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


def parse_tools(prompt):
    """Tool definitions from the clean system prompt: name, description and argument names."""
    tools = []
    for block in re.split(r"\n(?=Tool: )", prompt or ""):
        name = re.match(r"Tool:\s*(\S+)", block)
        if not name:
            continue
        description = re.search(r"^Description:\s*(.*?)(?=^Arguments:|\Z)", block, re.M | re.S)
        properties, required = {}, []
        arguments = re.search(r"^Arguments:\n((?:- .*\n?)*)", block, re.M)
        for line in (arguments.group(1).splitlines() if arguments else []):
            arg = re.match(r"- ([^:\s]+):\s*(.*?)\s*(\(required\))?\s*$", line)
            if not arg:
                continue
            properties[arg.group(1)] = {} if arg.group(2) == "No description" else {"description": arg.group(2)}
            if arg.group(3):
                required.append(arg.group(1))
        tools.append({"name": name.group(1), "description": description.group(1).strip() if description else "",
                      "inputSchema": {"type": "object", "properties": properties, **({"required": required} if required else {})}})
    return tools


def main():
    folder, out_path = sys.argv[1], sys.argv[2]
    data = json.load(open(f"{folder}/response_all.json", encoding="utf-8"))
    servers = data["servers"].values() if isinstance(data["servers"], dict) else data["servers"]
    written = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for server in servers:
            definitions = [tool for tool in parse_tools(server.get("clean_system_promot")) if tool["name"] in server["tool_names"]]
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
                            "tool_defs": definitions,
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
