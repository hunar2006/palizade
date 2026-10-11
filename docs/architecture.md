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

`palizade install-config <serverName>` writes a Claude Desktop `mcpServers` entry for the wrapper. The generated entry uses `process.execPath` and an absolute path to the running Palizade CLI instead of a shell shim, which avoids Windows `.cmd` and `.ps1` resolution pitfalls. Existing client config files are parsed, merged, backed up to `.bak`, and never overwritten if the JSON is malformed. Use `--client-config` for non-standard client config locations.

`palizade install-config --all` is the bulk protection path. It reads the target client config, skips entries already routed through Palizade, rewrites each remaining `mcpServers` entry in place, and stores the original upstream `command`, `args`, optional `cwd`, and optional `env` in `palizade.yaml` under `servers`. Auto-added servers default to `trust: untrusted` with empty `toolClasses`, which keeps the first run conservative while relying on built-in name and annotation heuristics until the operator tightens the config.

Bulk install prints lock-approval commands for newly added servers instead of starting them automatically. Starting arbitrary MCP servers during config installation can have side effects, so the explicit follow-up is:

```bash
palizade lock approve <serverName>
```

`palizade doctor` reports client config coverage by listing every configured MCP server and whether it is routed through Palizade. This coverage is limited to configured MCP servers. Native client tools, including Claude Code's built-in file and shell tools, bypass MCP and are not protected by Palizade.

## Interception Points

Protected writes resolve relative paths against the server working directory, expand home paths, normalize traversal/separators and resolve existing symlink ancestors even when the final file does not exist. Windows/macOS comparisons are case-insensitive. Built-in agent/client config, CI, shell profile, credential, policy/lock/allowlist and package.json targets can be extended with `protectedTargets.criticalPaths`. Uncertain resolution is treated as critical. `protectedTargets.maxDiffBytes` caps current/proposed file reads at 65536 bytes each; known write/edit forms produce escaped approval diffs, with tainted/sensitive content masked. Unknown edit formats explicitly report that a complete replacement was not supplied.

1. `initialize`
   - Forwarded and audited as session setup.
   - Server capability metadata is lock-checked and scanned.

2. `tools/list`
   - Hashes security-relevant descriptor fields including schemas, annotations, icons, titles, descriptions, and metadata.
   - Compares hashes against `palizade.lock`.
   - Scans tool descriptions.
   - Policy can block, log, require approval, or sanitize suspicious metadata.
   - Metadata review (`metadata-guard.ts`): every string and property name in each tool, including schema `description`, `default`, `enum` and `examples`, is checked for hidden Unicode (TAG characters are also decoded back to ASCII and run through the detectors), dangerous defaults, cross-server name collisions and shadowing. Tool names of every wrapped server are kept in `<stateDir>/tool-registry.sqlite`, shared by all Palizade processes using that state directory; only servers present in `palizade.yaml` are compared. Flagged tools get their own policy decision, so one bad tool is withheld without hiding the rest of the server. A registry or review error applies `defaults.on_error`.
   - `palizade lock approve` stores a canonical snapshot of each tool next to its hash, so `palizade lock diff` and `lock approve` can print a field by field diff with byte offsets and every non printing character escaped as `\u{XXXX}`.

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
   - Resource/prompt descriptors are lock-checked and scanned, including the hidden Unicode and shadowing checks; `server/discover` metadata gets the same scan.
   - `resources/read` and `prompts/get` content is scanned, tainted, sanitized, and audited through the same content-security path as tool results.

7. Elicitation and other server requests
   - `elicitation/*` is treated as privileged user interaction.
   - Non-allowlisted server-initiated requests are blocked.

## Streamable HTTP Transport

`packages/core/src/http.ts` implements an upstream HTTP client for both protocol eras; `packages/core/src/http-listener.ts` implements the transparent listener.

- Era detection is per message: `_meta["io.modelcontextprotocol/protocolVersion"]` marks the 2026-07-28 era, `initialize` marks the 2025-11-25 era. For `url` servers with `protocolVersion: auto`, a legacy POST that gets a 404/400 with a recognized modern JSON-RPC error (`-32601`, `-32020`, `-32000`, `-32001`) switches the transport to the modern era and synthesizes the initialize response for the stdio client.
- 2026-07-28: every message is its own POST with `Accept: application/json, text/event-stream`, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and `Mcp-Param-{Name}` headers (values base64-sentinel encoded via `=?base64?…?=` when not ASCII-safe). Responses are JSON or request-scoped SSE streams; notifications return 202. Servers pushing JSON-RPC requests on SSE are flagged as protocol violations and the message is dropped. Upstream header/body disagreements (`MCP-Protocol-Version`, `Mcp-Method`) are flagged and the response is rejected. Closing the SSE stream cancels the request.
- 2025-11-25: initialize handshake, `Mcp-Session-Id`, GET SSE stream with `Last-Event-ID` resumability, DELETE on close.
- Both eras refuse redirects while an `Authorization` header is set (tokens are never forwarded to redirect targets), refuse cross-origin redirects entirely, and mask tokens everywhere: no header value ever reaches audit, stderr, or the detector/taint stores.
- `palizade wrap <server>` with a `url` server runs the bridge: stdio client in, engine in the middle, HTTP upstream out.
- `palizade serve` binds `127.0.0.1` (unless `--allow-remote`), validates `Origin` as localhost-only, requires Palizade's own bearer token (`X-Palizade-Token`, generated at `init` into `.palizade/listener.token`), takes the upstream from config only, forwards the client's `Authorization` header unchanged to the configured upstream origin, passes 401/403/`WWW-Authenticate` through untouched for OAuth discovery, and applies the RFC 8707 rule: no TLS termination, no URL rewriting, no token minting.

## Dual-Era stdio (2026-07-28 MRTR)

The interceptor is era aware per message: `_meta["io.modelcontextprotocol/protocolVersion"]` marks 2026-07-28, `initialize` marks the legacy era. On the 2026-07-28 era:

- `resultType: "input_required"` tool/prompt/resource results are inspected. Each `inputRequests` entry is gated with the same policy methods the legacy server-initiated requests used (`sampling/createMessage`, `elicitation/create`, `roots/list`). Denied requests turn the whole result into a tool error. Form-mode elicitations requesting sensitive fields (passwords, API keys, tokens, payment data) are denied per spec; URL-mode elicitation URLs go through egress allowlist and taint checks. Blocked reasons are audited and never forwarded.
- The client's retry `inputResponses` are taint-matched like sink arguments.
- `notifications/tools/list_changed` is forwarded to the client and triggers a proxy-side `tools/list` re-lock: the synthetic response is compared against `palizade.lock`, drifted metadata is approval-gated, and the synthetic response is never forwarded.
- `server/discover` responses are lock-checked and scanned like `tools/list`.
- `subscriptions/listen` responses are scanned through the generic content path.
- `structuredContent` is scanned and taint-registered like `content` text; sanitize/spotlight applies to string fields only, keeping the result schema valid. `ttlMs`/`cacheScope` on list results are audited; the lockfile is re-verified on every refresh regardless of client caching.

## Sandboxed Launch

`packages/core/src/sandbox.ts` turns `servers.<name>.sandbox` into a launch plan; `packages/core/src/launch.ts` is the only place stdio upstreams are spawned (`wrap`, `lock approve`, `lock diff`). `none` (default) keeps the old behavior. Validation runs before any spawn: on Windows only `docker` is accepted, `bubblewrap` needs Linux and `seatbelt` needs macOS, and a `url` server with a sandbox is a config error.

- `docker`: `run --rm -i --init --security-opt no-new-privileges --cap-drop ALL --read-only --tmpfs /tmp --pids-limit 512`, the server `cwd` bind-mounted read-only at `/workspace`, `writable` paths bind-mounted read-write (`host` or `host::/container`), `HOME=/tmp`. Environment is never copied from the host: only `env` from `palizade.yaml` and `passEnv` names are passed, as `-e NAME` so values never appear in the argument list.
- `bubblewrap`: `--unshare-all --die-with-parent --new-session --cap-drop ALL`, system directories read-only, `cwd` read-only, `writable` paths bound read-write, filtered environment.
- `seatbelt`: `sandbox-exec -p <profile>` that denies writes outside `writable` and `/tmp`, and denies network unless allowlisted.
- `network: none` (default for sandboxed servers) removes networking. `network: allowlist` with `allowHosts` starts a per-launch HTTP/CONNECT egress proxy (`packages/core/src/egress-proxy.ts`): exact hosts or `*.suffix`, at most 64 connections, 120 s idle timeout, and a random proxy credential; every allow/deny is audited as `sandbox/egress`. With docker, `dockerNetwork` can name an internal network whose only route is the proxy.
- Every spawn is audited (`process/spawn`, action `log_only`) with the full command and arguments, secrets masked, environment as key names only. If the audit write fails the spawn is refused. `palizade doctor` lists unsandboxed servers and fails on an unsupported sandbox.

## Tool Classification

The coding preset checks Git pushes by resolving simple literal remotes with local `git remote get-url --push --all`, under a one-second/4096-byte bound. It makes no network call. Dynamic, compound or unsupported command forms require approval. Shell network command detection is deliberately conservative, not a complete shell parser.

The research preset checks every normalized/canonical file target against one configured output directory. It blocks critical paths even inside that directory, and rejects tools with network, remote-write, memory, execution or deletion capabilities. Source overrides remain an administrator trust decision.

Annotations from semi/untrusted servers can raise risk but cannot lower it. `readOnlyHint` is ignored for classification/capability derivation on those servers; explicit administrator overrides still take priority. Trusted servers keep the prior annotation behavior, consistent with the 2026-07-28 MCP tools trust requirement.

Argument roles can be overridden by `servers.<name>.argumentRoles.<tool>.<jsonPath>`. Paths use `$.field`, nested properties and `[*]` array members (the leading `$.` is optional). Built-in mappings recognize GitHub owner/repo, Slack channel/channel_id, mail to/cc/bcc and fetch/http URL fields by tool name. `channel_id` and `account_id` are destination roles.

Derivation order:

1. `palizade.yaml` tool-class and capability overrides.
2. MCP annotations.
3. Built-in and name/argument heuristics.
4. `unknown`.

The internal model uses capability flags such as `network_egress`, `sends_message`, `file_write`, `writes_local`, and `executes_code`. `source`, `sink`, `pure`, and `unknown` remain as derived labels for backward-compatible policies. Unknown tools are blocked on untrusted servers, approval-gated on semi-trusted servers, and audit-logged on trusted servers.

## Shared Taint

Memory/vector writes carry `persists_memory`. When an observable tainted write is approved, its original fingerprints become persistent untrusted provenance with no TTL; transformed written fields also receive persistent fingerprints linked to original IDs. Later matching memory reads retain original source identity and IDs in audit `taintSources`. Persistent records remain within their profile but match across subsequent logical runs. `taint prune` preserves these records unless `--include-persistent` is explicitly supplied.

Sink attempts (including denied attempts) update shared session counters atomically. The rolling minute stores timestamps; distinct destinations and repeated tool/argument signatures are HMACs in SQLite. Tracking is bounded by `limits.historyEntries` (1000); exhaustion gates further sinks rather than dropping evidence. Repeats and destination counts last for the logical session, while call-rate timestamps expire after one minute.

High-score source/tool responses (default 0.85) and hard blocks on tainted/split/lookalike destinations start shared quarantine. It expires after `taint.quarantine.turns` (20 sink attempts) or `ttlMs` (1800000), whichever occurs first. Start/end/clear events are audited separately. Session destination grants do not suppress quarantine. Expiry is evaluated on the next sink attempt.

Session flags `seenUntrusted` and `seenSensitive` persist in SQLite. They follow the configured session scope; profile mode shares one logical session across wrapped processes. When `PALIZADE_RUN_ID` is supplied, flags and session grants are isolated by profile plus run ID, even with profile taint scope. Process scope keeps sessions independent. Without a host run ID, profile flags remain conservative across launches. Session destination grants are bounded to 1024 HMACs and never bypass hard blocks.

Outbound sink calls keep a memory-only rolling payload window for each session and destination. `taint.window` defaults to 12 calls, 900000 ms TTL, 262144 bytes per window and 256 destinations. Concatenated payloads are decoded and matched; only sensitive records gain eight-character shard fingerprints, HMAC-protected in SQLite. Window matches exclude temporal-only hits. The window is process-local and bounded; it cannot correlate shards across distinct wrapper processes.

Learned egress grants live in the separate `egress.learnedFile` (default `palizade.allow.yaml`, relative to config). It is validated at startup and before each sink call. Remember writes use an exclusive lock and atomic replacement; lock contention fails closed. Hard policy blocks always win over egress approvals. Source-call destinations are not egress-gated.

Sink fields and the flattened argument text are expanded into bounded decoded candidates before matching both taint classes. Original payloads are retained, and ingestion never decodes. `taint.decode.maxDepth` defaults to 2 and `maxBytes` to 262144 total decoded bytes; exceeding the budget follows policy `on_error`. Supported views include base64/base64url, hex, percent encoding, common HTML entities, JS escapes, UTF-8 RFC 2047 B/Q and punycode. Audit `matchReasons` records `decoded:<kind>` without payloads.

Matching strips TAG characters, variation selectors, soft hyphens and invisible operators in a separate view. Display content stays unchanged unless policy sanitizes it. Common Cyrillic/Greek lookalikes and fullwidth forms are folded only for domain and identifier tokens; prose is not folded. Host tokens include ASCII and skeleton views. The heuristic detector scans the stripped view with original span offsets and reports `hidden_unicode` counts and escaped code points.

Runtime taint uses `.palizade/taint.sqlite` by default. The store scope defaults to `profile`, so separate wrapped processes using the same profile can match observable taint until TTL expiry. `PALIZADE_RUN_ID` enables stronger host-provided run correlation. Raw exact fragments and tokens are HMAC-protected with `.palizade/taint.key`; SimHash is retained for fuzzy comparison.

Taint records carry classes. Existing records default to `untrusted`; new sensitive records use the same exact, token, fuzzy, TTL, and SQLite machinery. A value can be both `untrusted` and `sensitive`, which is how a fetched secret can later be blocked at an egress sink without a second detector hit.

Sensitive origins can be declared per server, per tool, or by path-pattern hints in `palizade.yaml`. This is useful for tools like secrets managers where the output is sensitive by provenance even if it does not match a built-in pattern.

## Audit

Audit events include event ID, timestamp, session/profile/scope/run identifiers where configured, server, tool, direction, method, taint IDs, detector score and labels, matched policy rule, action, reason, latency, payload hash, and a hash-chain pair. Egress metadata includes taint classes, argument roles, redaction status, and allowlist destination status. Raw payload capture is off by default; when enabled, detected secrets/PII are masked before the payload is handed to the audit logger. The hash chain is tamper-evident only if logs are protected; it is not tamper-proof.

## Simplifications

- Stdio and Streamable HTTP are both implemented; the transparent listener shares one upstream session per served server (use the stdio bridge for per-client legacy sessions).
- Optional model support is externally configured and must pass `palizade detectors verify` before being described as active.
- Secret and PII detection is pattern-based and high-precision by design; custom, transformed, split, or obfuscated secrets can be missed. Egress allowlists and taint/provenance rules are the structural controls.
- Fuzzy matching is lightweight SimHash, not semantic equivalence.
- Prompt Guard 2 is opt-in because downloading the model during every `init` would make the default DX heavy.
