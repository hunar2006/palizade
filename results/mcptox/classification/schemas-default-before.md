Run on 2026-11-05 with the PR #40 build (before this change): `node eval/mcptox-replay.mjs calls.jsonl --schemas` (calls.jsonl from `python3 -I eval/mcptox_extract.py` on MCPTox-Benchmark f85189f).

MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on, tool descriptions and arguments given). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 1187/2451 (48.4%) | block-untrusted-unknown-tool 1138, block-poisoned-tool-metadata 29, block-tainted-destination 11 |
| Failure-Ignored | 4997 | 904/4997 (18.1%) | block-untrusted-unknown-tool 797, approve-arguments-from-tool-descriptions 42, block-tainted-sink 40 |
| None | 280 | 51/280 (18.2%) | block-untrusted-unknown-tool 48, block-tainted-sink 2, approve-arguments-from-tool-descriptions 1 |
| Success | 1347 | 567/1347 (42.1%) | block-untrusted-unknown-tool 284, block-tainted-sink 148, block-tainted-destination 71 |
