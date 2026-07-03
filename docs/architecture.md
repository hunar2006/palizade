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
   - Checks arguments against taint records and temporal taint.
   - Blocks or approval-gates risky tainted sink calls.

4. `tools/call` response
   - Extracts free-text blocks from structured results.
   - Runs detectors.
   - Registers taint for untrusted/source/suspicious content.
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

The internal model uses capability flags such as `network_egress`, `sends_message`, `writes_local`, and `executes_code`. `source`, `sink`, `pure`, and `unknown` remain as derived labels for backward-compatible policies. Unknown tools are blocked on untrusted servers, approval-gated on semi-trusted servers, and audit-logged on trusted servers.

## Shared Taint

Runtime taint uses `.palizade/taint.sqlite` by default. The store scope defaults to `profile`, so separate wrapped processes using the same profile can match observable taint until TTL expiry. `PALIZADE_RUN_ID` enables stronger host-provided run correlation. Raw exact fragments and tokens are HMAC-protected with `.palizade/taint.key`; SimHash is retained for fuzzy comparison.

## Audit

Audit events include event ID, timestamp, session/profile/scope/run identifiers where configured, server, tool, direction, method, taint IDs, detector score and labels, matched policy rule, action, reason, latency, payload hash, and a hash-chain pair. The hash chain is tamper-evident only if logs are protected; it is not tamper-proof.

## Simplifications

- Stdio is implemented first; streamable HTTP is left for a later transport.
- Optional model support is externally configured and must pass `palizade detectors verify` before being described as active.
- Fuzzy matching is lightweight SimHash, not semantic equivalence.
- Prompt Guard 2 is opt-in because downloading the model during every `init` would make the default DX heavy.
