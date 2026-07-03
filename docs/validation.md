# Validation

Last run: 2026-07-03 on Windows, Node.js v22.21.0, pnpm v11.7.0.

## Automated Checks

| Command | Result |
| --- | --- |
| `pnpm install` | Passed; workspace package metadata regenerated after the Palizade rename. |
| `pnpm build` | Passed; TypeScript build and bundled `packages/cli/dist/index.cjs`. |
| `pnpm test` | Passed; 10 files, 32 tests. Node printed the expected experimental `node:sqlite` warning. |
| `pnpm eval` | Passed; replay blocks poisoned metadata, tainted sink reuse, and server sampling; sanitizes suspicious untrusted output. |
| `pnpm eval:asr` | Passed; local MCP ASR proxy table: off ASR 30/30, default ASR 0/30 with 0/22 FP, strict ASR 0/30 with 2/22 FP. |
| `pnpm eval:promptguard2` | Passed; standalone PromptGuard2 local corpus result: 10/30 malicious detected, 0/22 benign false positives. |
| `pnpm eval:combined` | Passed; heuristic + PromptGuard2 result: 30/30 malicious detected, 0/22 benign false positives. |
| `pnpm demo:cross-server` | Passed; separate fetch and Gmail engines share SQLite profile taint and block the Gmail send. |
| `pnpm bench:latency` | Passed; p50 0.07 ms, p95 0.17 ms across 500 iterations. |
| `pnpm smoke:filesystem` | Passed against `@modelcontextprotocol/server-filesystem`; 14 tools, 1 README content block, 655434-byte large payload. |
| `node packages/cli/dist/index.cjs detectors verify heuristic` | Passed; benign score 0, injection score 1. |
| `node packages/cli/dist/index.cjs detectors install promptguard2` | Passed; downloaded `sinatras/Llama-Prompt-Guard-2-86M-ONNX` into `.palizade/models`. |
| `node packages/cli/dist/index.cjs -c palizade.promptguard2.yaml detectors verify promptguard2` | Passed; benign score 0.0006, injection score 0.9979 on CPU. |
| `node packages/cli/dist/index.cjs audit verify` | Passed; 7 hashed events across 1 segment verified. |
| `node packages/cli/dist/index.cjs taint prune` | Passed; pruned 0 records. |
| `node packages/cli/dist/index.cjs doctor` | Passed; loaded local config, policy, lockfile, audit path, toy server, and filesystem server. |
| `pnpm pack` | Passed; root tarball excludes `.palizade`, local logs, local DBs, and `node_modules`. |
| `pnpm --filter palizade pack --pack-destination .palizade/smoke` | Passed; produced `.palizade/smoke/palizade-0.1.0.tgz`. |
| `npm exec --yes --package .palizade/smoke/palizade-0.1.0.tgz -- palizade --help` | Passed; packed CLI starts and prints command help. |
| `npm view palizade version` | Passed; npm registry reports `0.1.0`. |
| `npm exec --yes --package palizade -- palizade --help` | Passed from a clean temp directory; published CLI installs and prints command help. |

## Local Regression Corpus

`eval/protocol-regression.mjs` is a local MCP-oriented corpus, not an AgentDojo/InjecAgent ASR benchmark.

| Suite | Result |
| --- | --- |
| Fixtures | 52 total: 30 malicious, 22 benign |
| Malicious detection rate | 30/30 (100.0%) |
| Benign false-positive rate | 0/22 (0.0%) |

The corpus includes tool metadata poisoning, prompt/resource content poisoning, server-initiated sampling/elicitation text, secret query exfiltration, URL and recipient exfiltration, shell hazards, base64/hex payloads, invisible Unicode, XML/chat role spoofing, Hindi instruction override text, and benign lookalikes.

## Detector Modes

| Detector mode | Malicious detection rate | Benign false-positive rate |
| --- | ---: | ---: |
| heuristic | 30/30 (100.0%) | 0/22 (0.0%) |
| promptguard2 | 10/30 (33.3%) | 0/22 (0.0%) |
| combined | 30/30 (100.0%) | 0/22 (0.0%) |

## Manual Checks Still Required

- Claude Desktop or Claude Code manual client validation with wrapped `filesystem` and any launch-demo servers.
- Manual approval UX check in the real client environment, especially headless client spawn behavior.
- Explicit `palizade detectors install promptguard2` and `palizade detectors verify promptguard2` if claiming model-backed detection.
- AgentDojo/InjecAgent-derived benchmark table. The current eval is local regression coverage only.
- Release tasks: demo GIF and launch/community posts.
