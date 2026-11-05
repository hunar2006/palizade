Run on 2026-11-05 with the this branch: `node eval/mcptox-replay.mjs calls.jsonl` (calls.jsonl from `python3 -I eval/mcptox_extract.py` on MCPTox-Benchmark f85189f).

MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 873/2451 (35.6%) | block-untrusted-unknown-tool 823, block-poisoned-tool-metadata 29, block-tainted-destination 11 |
| Failure-Ignored | 4997 | 1028/4997 (20.6%) | block-untrusted-unknown-tool 983, block-poisoned-tool-metadata 24, approve-arguments-from-tool-descriptions 20 |
| None | 280 | 67/280 (23.9%) | block-untrusted-unknown-tool 66, approve-arguments-from-tool-descriptions 1 |
| Success | 1347 | 553/1347 (41.1%) | block-untrusted-unknown-tool 291, block-tainted-sink 99, approve-arguments-from-tool-descriptions 82 |
