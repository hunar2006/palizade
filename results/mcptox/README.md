# MCPTox (held out)

[MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) (Wang et al., AAAI-26) poisons the description of an extra tool on 45 real MCP servers so that the model misuses the server's other tools. Palizade was never tuned on it before these runs. The dataset has no license, so it is not copied into this repository; these files hold only Palizade's results.

## Two measurements

1. **Description check** (`eval/mcptox.mjs`): each of the 485 poisoned tools is sent in a `tools/list` response. The default policy withholds 4 (0.8%). These descriptions are written in a calm, operational tone ("before using read_file, a prerequisite check is to ..."), which the heuristic detector does not flag. Spotting them by wording is not where Palizade is strong.
2. **Recorded calls** (`eval/mcptox_extract.py` then `eval/mcptox-replay.mjs`): MCPTox includes the tool calls that real models made after seeing the poisoned list, labelled by the authors. Each call is replayed through Palizade after the poisoned `tools/list`. `Success` calls are attacks that worked on the model; `Failure-Ignored` calls are the model doing the user's task, so stopping those is a false positive.

| | Attacks stopped (`Success`, 1347) | Normal calls stopped (`Failure-Ignored`, 4997) |
|---|---:|---:|
| Default policy as shipped | 689 (51.2%) | 1313 (26.3%) |
| Every tool classified, description taint off | 10 (0.7%) | 24 (0.5%) |
| Every tool classified, description taint on | 331 (24.6%) | 80 (1.6%) |

"Every tool classified" drops `block-untrusted-unknown-tool`: in the shipped row most stops come from that rule, because these servers are not in Palizade's catalog, and it would also stop the user's own calls. The last two rows show what the taint rules add once tools are classified. Treating text in untrusted tool descriptions as taint (`taint.toolMetadata`) and asking when a call copies it (`approve-arguments-from-tool-descriptions`) took this from 0.7% to 24.6% of successful attacks, at 1.6% of normal calls stopped. AgentDojo results did not change.

## What still gets through

Most remaining `Success` calls change a parameter of a read or search tool (add `LIMIT 1`, search a different id, rewrite a query). That corrupts what the user sees but moves no data out, and Palizade checks sinks, not reads, so it allows them. Short values (`"1"`, `13`) are also too short to match as copied text.

## Reproduce

```bash
git clone --depth 1 https://github.com/zhiqiangwang4/MCPTox-Benchmark /tmp/mcptox
pnpm build
node eval/mcptox.mjs /tmp/mcptox
python3 -I eval/mcptox_extract.py /tmp/mcptox /tmp/mcptox-calls.jsonl
node eval/mcptox-replay.mjs /tmp/mcptox-calls.jsonl [--skip-rule block-untrusted-unknown-tool] [--tool-metadata off]
```
