Run on 2026-11-05 with the PR #40 build (before this change): `node eval/mcptox-replay.mjs calls.jsonl --schemas --skip-rule block-untrusted-unknown-tool` (calls.jsonl from `python3 -I eval/mcptox_extract.py` on MCPTox-Benchmark f85189f).

MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on, tool descriptions and arguments given, without block-untrusted-unknown-tool). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 50/2451 (2.0%) | block-poisoned-tool-metadata 29, block-tainted-destination 11, block-tainted-sink 5 |
| Failure-Ignored | 4997 | 182/4997 (3.6%) | approve-arguments-from-tool-descriptions 117, block-tainted-sink 40, block-poisoned-tool-metadata 24 |
| None | 280 | 3/280 (1.1%) | block-tainted-sink 2, approve-arguments-from-tool-descriptions 1 |
| Success | 1347 | 301/1347 (22.3%) | block-tainted-sink 148, block-tainted-destination 71, approve-arguments-from-tool-descriptions 60 |
