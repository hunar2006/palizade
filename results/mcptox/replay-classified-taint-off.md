MCPTox recorded calls through Palizade (default policy, untrusted server, tool description taint off, without block-untrusted-unknown-tool). Stopped means blocked, or an approval prompt the user refused.

| MCPTox label | Calls | Stopped | Top rules |
|---|---:|---:|---|
| Failure-Direct Execution | 2451 | 30/2451 (1.2%) | block-poisoned-tool-metadata 29, approve-critical-path 1 |
| Failure-Ignored | 4997 | 24/4997 (0.5%) | block-poisoned-tool-metadata 24 |
| None | 280 | 0/280 (0.0%) |  |
| Success | 1347 | 10/1347 (0.7%) | approve-critical-path 10 |
