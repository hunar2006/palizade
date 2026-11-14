# Fewer false blocks on unknown tools

Under the shipped default policy, the main source of false blocks in the MCPTox replay is `block-untrusted-unknown-tool`: tools on untrusted servers that Palizade cannot classify are blocked. This change classifies more of them from tool names and input schemas, and lets `palizade learn` propose classes for the rest, for the user to confirm.

## How the rules were chosen

Only on the development set, `eval/classifier-devset.mjs`: the 321 real tools of the 25 catalogued servers (`packages/core/src/real-server-tools.fixture.json`), classified as if their server were not in the catalog, compared with the catalog's class. MCPTox and AgentDojo were not used to choose rules; for MCPTox only the aggregate counts below were looked at.

| Dev set (2026-11-05) | Unknown, before | after | Sink classified as source or pure, before | after |
|---|---:|---:|---:|---:|
| Full tool definitions (`node eval/classifier-devset.mjs`) | 53 | 19 | 1 | 0 |
| Tool names only (`--names-only`) | 122 | 40 | 5 | 2 |

The new name words are actions (click, fill, start, stop, deploy, merge, kill, install, connect, ...), which make a tool a sink, and reads (status, diff, log, show, info, describe, inspect, find, retrieve, check, screenshot, ...), which make it a source. They are matched in tool names only, since descriptions say "start with" or "stop when" all the time. The new schema signals are plural `urls`/`links` (network egress) and `prompt` (invokes a model). On untrusted servers a schema can still only add capabilities.

Classifying an unknown tool as a sink never allows more than before: a sink with tainted arguments is still blocked, and output from untrusted servers is tainted whatever the class. Classifying one as a source does allow tainted arguments; the read words are the same kind of evidence the existing `read`/`get`/`search`/`list` words already were.

## MCPTox (held out)

`Success` calls are attacks that worked on the model; `Failure-Ignored` calls are the model doing the user's task, so stopping those is a false positive. The original replay gives Palizade only tool names; `--schemas` also gives each tool's description and argument names from the dataset's clean system prompt, which is closer to what a real server sends.

| Replay (2026-11-05) | Attacks stopped, before | after | Normal calls stopped, before | after |
|---|---:|---:|---:|---:|
| Default policy, tool names only | 689/1347 (51.2%) | 553/1347 (41.1%) | 1313/4997 (26.3%) | 1028/4997 (20.6%) |
| Default policy, descriptions and arguments | 567/1347 (42.1%) | 470/1347 (34.9%) | 904/4997 (18.1%) | 676/4997 (13.5%) |
| Every tool classified, tool names only | 331/1347 (24.6%) | 308/1347 (22.9%) | 80/4997 (1.6%) | 80/4997 (1.6%) |
| Every tool classified, descriptions and arguments | 301/1347 (22.3%) | 314/1347 (23.3%) | 182/4997 (3.6%) | 182/4997 (3.6%) |

Fewer attacks are stopped under the default policy too: many of them were stopped only because the unknown tool rule blocks everything on those servers, including the user's own calls (291 of the 553 remaining, and 167 of the 470, still come from that rule). Attacks stopped by the taint rules, the "every tool classified" rows, moved by 23 down and 13 up. "Before" is the build of PR #40; each file in this folder has the exact command.

## AgentDojo

Not rerun here: the replay needs `pip install agentdojo==0.1.35`, which this session was not allowed to install. The AgentDojo workflow (`.github/workflows/agentdojo.yml`, run by hand with `workflow_dispatch`) replays the default preset and fails if attack success rises or clean utility falls against `results/agentdojo/user-intent`.
