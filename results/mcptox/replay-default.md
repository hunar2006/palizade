MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint on). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 1187/2451 (48.4%) | block-untrusted-unknown-tool 1138, block-poisoned-tool-metadata 29, block-tainted-destination 11 |
| Failure-Ignored | 4997 | 1313/4997 (26.3%) | block-untrusted-unknown-tool 1268, block-poisoned-tool-metadata 24, approve-arguments-from-tool-descriptions 20 |
| None | 280 | 113/280 (40.4%) | block-untrusted-unknown-tool 112, approve-arguments-from-tool-descriptions 1 |
| Success | 1347 | 689/1347 (51.2%) | block-untrusted-unknown-tool 449, block-tainted-sink 99, approve-arguments-from-tool-descriptions 75 |
