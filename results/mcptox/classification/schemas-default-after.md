Run on 2026-11-05 with the this branch: `node eval/mcptox-replay.mjs calls.jsonl --schemas` (calls.jsonl from `python3 -I eval/mcptox_extract.py` on MCPTox-Benchmark f85189f).

MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on, tool descriptions and arguments given). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 873/2451 (35.6%) | block-untrusted-unknown-tool 823, block-poisoned-tool-metadata 29, block-tainted-destination 11 |
| Failure-Ignored | 4997 | 676/4997 (13.5%) | block-untrusted-unknown-tool 569, approve-arguments-from-tool-descriptions 42, block-tainted-sink 40 |
| None | 280 | 35/280 (12.5%) | block-untrusted-unknown-tool 32, block-tainted-sink 2, approve-arguments-from-tool-descriptions 1 |
| Success | 1347 | 470/1347 (34.9%) | block-untrusted-unknown-tool 167, block-tainted-sink 148, block-tainted-destination 84 |
