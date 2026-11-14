Run on 2026-11-05 with the PR #40 build (before this change): `node eval/mcptox-replay.mjs calls.jsonl --skip-rule block-untrusted-unknown-tool` (calls.jsonl from `python3 -I eval/mcptox_extract.py` on MCPTox-Benchmark f85189f).

MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on, without block-untrusted-unknown-tool). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 50/2451 (2.0%) | block-poisoned-tool-metadata 29, block-tainted-destination 11, block-tainted-sink 5 |
| Failure-Ignored | 4997 | 80/4997 (1.6%) | approve-arguments-from-tool-descriptions 55, block-poisoned-tool-metadata 24, block-tainted-destination 1 |
| None | 280 | 2/280 (0.7%) | approve-arguments-from-tool-descriptions 2 |
| Success | 1347 | 331/1347 (24.6%) | approve-arguments-from-tool-descriptions 166, block-tainted-sink 99, block-tainted-destination 58 |
