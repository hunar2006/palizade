# Architecture

Palizade is deliberately small at the transport edge and strict at the policy edge.

## Runtime Flow

```text
client stdin/stdout
  -> LineJsonRpcPeer
  -> InterceptionEngine
  -> LineJsonRpcPeer
  -> upstream MCP server child process
```

The current transport is strict newline-delimited JSON-RPC over stdio, matching the official TypeScript MCP SDK transport. Content-Length framing and JSON-RPC batches are disabled by default and must be enabled with explicit compatibility flags.

## Configuration Loading

`palizade.yaml` is resolved relative to the caller's current working directory only long enough to locate the file. After parsing, every Palizade-owned path field is resolved relative to the config file's own directory: `stateDir`, `policy`, `lockfile`, audit paths, taint paths, and detector cache paths. This keeps Claude Desktop and other clients from breaking local relative paths when they spawn Palizade from an arbitrary working directory. Server commands and args remain opaque; Palizade does not rewrite upstream server arguments.

## Client Config Installation

`palizade install-config <serverName>` writes a Claude Desktop `mcpServers` entry for the wrapper. The generated entry uses `process.execPath` and an absolute path to the running Palizade CLI instead of a shell shim, which avoids Windows `.cmd` and `.ps1` resolution pitfalls. Existing client config files are parsed, merged, backed up to `.bak`, and never overwritten if the JSON is malformed.

`palizade install-config --all` is the bulk protection path. It reads the target client config, skips entries already routed through Palizade, rewrites each remaining `mcpServers` entry in place, and stores the original upstream `command`, `args`, optional `cwd`, and optional `env` in `palizade.yaml` under `servers`. Auto-added servers default to `trust: untrusted` with empty `toolClasses`, which keeps the first run conservative while relying on built-in name and annotation heuristics until the operator tightens the config.

Bulk install prints lock-approval commands for newly added servers instead of starting them automatically. Starting arbitrary MCP servers during config installation can have side effects, so the explicit follow-up is:

```bash
palizade lock approve <serverName>
```

`palizade doctor` reports client config coverage by listing every configured MCP server and whether it is routed through Palizade. This coverage is limited to MCP servers. Native client tools, including Claude Code's built-in file and shell tools, bypass MCP and are not protected by Palizade.

## Interception Points

1. `initialize`
   - Forwarded and audited as session setup.
   - Server capability metadata is lock-checked and scanned.

2. `tools/list`
   - Hashes security-relevant descriptor fields including schemas, annotations, icons, titles, descriptions, and metadata.
   - Compares hashes against `palizade.lock`.
   - Scans tool descriptions.
   - Policy can block, log, require approval, or sanitize suspicious metadata.

3. `tools/call` request
   - Classifies target tool as `source`, `sink`, `pure`, or `unknown`.
   - Flattens string arguments.
   - Extracts argument roles such as URL, hostname, email recipient, body, file path, and query.
   - Checks arguments against untrusted and sensitive taint records, direct secret/PII detector hits, destination allowlists, and temporal taint.
   - Blocks, redacts, or approval-gates risky tainted sink calls.

4. `tools/call` response
   - Extracts free-text blocks from structured results.
   - Runs detectors.
   - Registers `untrusted` taint for untrusted/source/suspicious content.
   - Registers `sensitive` taint for secret/PII detector hits or config-declared sensitive origins.
   - Applies policy actions such as spotlighting or span redaction.

5. Server-initiated sampling
   - `sampling/createMessage` is treated as privileged model access.
   - The default policy blocks it.

6. Resources and prompts
   - Resource/prompt descriptors are lock-checked and scanned.
   - `resources/read` and `prompts/get` content is scanned, tainted, sanitized, and audited through the same content-security path as tool results.

7. Elicitation and other server requests
   - `elicitation/*` is treated as privileged user interaction.
   - Non-allowlisted server-initiated requests are blocked.

## Tool Classification

Derivation order:

1. `palizade.yaml` tool-class and capability overrides.
2. MCP annotations.
3. Built-in and name/argument heuristics.
4. `unknown`.

The internal model uses capability flags such as `network_egress`, `sends_message`, `file_write`, `writes_local`, and `executes_code`. `source`, `sink`, `pure`, and `unknown` remain as derived labels for backward-compatible policies. Unknown tools are blocked on untrusted servers, approval-gated on semi-trusted servers, and audit-logged on trusted servers.

## Shared Taint

Runtime taint uses `.palizade/taint.sqlite` by default. The store scope defaults to `profile`, so separate wrapped processes using the same profile can match observable taint until TTL expiry. `PALIZADE_RUN_ID` enables stronger host-provided run correlation. Raw exact fragments and tokens are HMAC-protected with `.palizade/taint.key`; SimHash is retained for fuzzy comparison.

Taint records carry classes. Existing records default to `untrusted`; new sensitive records use the same exact, token, fuzzy, TTL, and SQLite machinery. A value can be both `untrusted` and `sensitive`, which is how a fetched secret can later be blocked at an egress sink without a second detector hit.

Sensitive origins can be declared per server, per tool, or by path-pattern hints in `palizade.yaml`. This is useful for tools like secrets managers where the output is sensitive by provenance even if it does not match a built-in pattern.

## Audit

Audit events include event ID, timestamp, session/profile/scope/run identifiers where configured, server, tool, direction, method, taint IDs, detector score and labels, matched policy rule, action, reason, latency, payload hash, and a hash-chain pair. Egress metadata includes taint classes, argument roles, redaction status, and allowlist destination status. Raw payload capture is off by default; when enabled, detected secrets/PII are masked before the payload is handed to the audit logger. The hash chain is tamper-evident only if logs are protected; it is not tamper-proof.

## Simplifications

- Stdio is implemented first; streamable HTTP is left for a later transport.
- Optional model support is externally configured and must pass `palizade detectors verify` before being described as active.
- Secret and PII detection is pattern-based and high-precision by design; custom, transformed, or obfuscated secrets can be missed.
- Fuzzy matching is lightweight SimHash, not semantic equivalence.
- Prompt Guard 2 is opt-in because downloading the model during every `init` would make the default DX heavy.
