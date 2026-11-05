# Hook latency

Wall clock time of one native hook call, measured the way the client runs it: a new process gets a pre tool shell call (`ls -la`) on stdin and prints a decision. Each run is 100 calls per client after 3 warm up calls, against a fresh `palizade init` project on the default policy. The first row is the cost of starting Node with no work, which no hook can go below.

Machine: Linux container, Node 22.23.4, 2026-11-05. The three runs below were made back to back. Run to run noise on this machine was large: in three other runs of each, the no daemon p50 ranged from 168.8 to 201.8 ms on the earlier build and from 169.3 to 279.4 ms on this one, with no client consistently slower on either.

## Before: the build without the daemon (PR #38)

Command: `node eval/hook-latency.mjs --iterations 100 --cli <PR #38 build>/index.cjs`

| Client | p50 ms | p95 ms |
|---|---:|---:|
| node -e "" (process start only) | 30.2 | 35.9 |
| claude-code | 186.4 | 228.1 |
| cursor | 184.0 | 227.6 |
| codex | 178.9 | 229.1 |
| gemini | 175.7 | 218.2 |

## After, no daemon running (the hook runs in process, as before)

Command: `node eval/hook-latency.mjs --iterations 100`

| Client | p50 ms | p95 ms |
|---|---:|---:|
| node -e "" (process start only) | 27.8 | 36.2 |
| claude-code | 185.3 | 228.2 |
| cursor | 186.0 | 227.6 |
| codex | 180.0 | 223.9 |
| gemini | 181.1 | 222.7 |

## After, with `palizade daemon` running

Command: `node eval/hook-latency.mjs --iterations 100 --daemon`

| Client | p50 ms | p95 ms |
|---|---:|---:|
| node -e "" (process start only) | 30.8 | 39.8 |
| claude-code | 53.5 | 64.1 |
| cursor | 54.2 | 73.5 |
| codex | 49.0 | 59.5 |
| gemini | 52.7 | 65.2 |

## Where the time goes without the daemon

One CPU profile of a single `palizade hook claude-code` call (`node --cpu-prof`), 226 ms total: loading and compiling the 1.5 MB bundle about 90 ms, parsing and validating `palizade.yaml` and the policy (YAML and zod) about 45 ms, creating the hook engine about 17 ms, opening SQLite about 12 ms, and checking the call about 21 ms. With the daemon, the hook process loads only a 6.7 KB client, and the daemon reuses the parsed config and policy while their text is unchanged.
