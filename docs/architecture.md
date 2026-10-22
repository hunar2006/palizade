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

Stdio uses strict newline-delimited JSON-RPC; Content-Length framing and JSON-RPC batches require explicit compatibility flags. URL servers use the Streamable HTTP transport described below. Both feed the same interception engine; native client hooks synthesize events for that engine.

## Configuration Loading

`palizade.yaml` is resolved relative to the caller's current working directory only long enough to locate the file. After parsing, every Palizade-owned path field is resolved relative to the config file's own directory: `stateDir`, `policy`, `lockfile`, audit paths, taint paths, and detector cache paths. This keeps Claude Desktop and other clients from breaking local relative paths when they spawn Palizade from an arbitrary working directory. Server commands and args remain opaque; Palizade does not rewrite upstream server arguments.

Schema errors in `palizade.yaml`, policy files and `palizade.allow.yaml` (`packages/policy/src/errors.ts`) list every problem (up to 20) with its YAML path, line number and a one line fix hint, for example `servers.fs.trsut (line 4): Unknown key 'trsut'` / `fix: Did you mean 'trust'?`. Messages never include the rejected value, so a misplaced token in `headers` or `env` is not echoed.

Hot reload (`packages/core/src/hot-reload.ts`) is on for `wrap` and `serve` unless `reload.enabled: false`. It polls `palizade.yaml`, the policy file and the learned allowlist every `reload.intervalMs` (1000 ms) with `fs.watchFile`, which works on Windows and with editors that replace files on save. A change is validated in full first (files over 1 MiB are rejected) and then swapped into the engine in one assignment; a config that points at an invalid policy is rejected as a whole. On a bad file the previous version stays active, a `config/reload` audit event records the error, and stderr gets a warning; successful reloads are audited with the new policy hash. Settings held outside the engine (state dir, audit and taint stores, detectors, transport, listener, approvals, metrics, and the server's command, url, env or sandbox) are reported as needing a restart. The learned allowlist is still re-read before each sink call; with hot reload on, an invalid edit keeps the last valid allowlist instead of failing every sink call, and with it off the old fail-closed behavior is unchanged. Startup still fails if any file is invalid, so Palizade never runs without a policy.

Optional `metrics.jsonl` (`packages/audit/src/metrics.ts`) is an extra audit sink that writes one line per decision: timestamp, server, tool, method, direction, action, rule id, latency, taint and label counts, a detector score bucket, and running per-action counters. It never writes payloads, reasons, labels or argument text, rotates to `<file>.1` at `metrics.maxBytes` (64 MiB), and a write failure is reported once on stderr without affecting the decision.

## Client Config Installation

`palizade install-config <serverName>` writes a Claude Desktop `mcpServers` entry for the wrapper. The generated entry uses `process.execPath` and an absolute path to the running Palizade CLI instead of a shell shim, which avoids Windows `.cmd` and `.ps1` resolution pitfalls. Existing client config files are parsed, merged, backed up to `.bak`, and never overwritten if the JSON is malformed. Use `--client-config` for non-standard client config locations.

`palizade install-config --all` is the bulk protection path. It reads the target client config, skips entries already routed through Palizade, rewrites each remaining `mcpServers` entry in place, and stores the original upstream `command`, `args`, optional `cwd`, and optional `env` in `palizade.yaml` under `servers`. Auto-added servers default to `trust: untrusted` with empty `toolClasses`, which keeps the first run conservative while relying on built-in name and annotation heuristics until the operator tightens the config.

Bulk install prints lock-approval commands for newly added servers instead of starting them automatically. Starting arbitrary MCP servers during config installation can have side effects, so the explicit follow-up is:

```bash
palizade lock approve <serverName>
```

`palizade doctor` reports configured MCP server coverage and sandbox state. Native client tools bypass MCP and need the separately installed hooks described below; doctor does not prove that those hooks are active in a live client.

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
- `palizade serve` defaults to loopback, validates localhost origins, requires its own `X-Palizade-Token`, takes upstreams only from config and forwards upstream authorization only to that configured origin. 401/403/challenges pass through. Tokens must have the upstream audience: this is not a validated OAuth-terminating gateway, and no token issuance/audience conversion is implemented. Avoiding TLS termination alone does not prove compliance with the [MCP token-passthrough restriction](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough).

## Dual-Era stdio (2026-07-28 MRTR)

The interceptor is era aware per message: `_meta["io.modelcontextprotocol/protocolVersion"]` marks 2026-07-28, `initialize` marks the legacy era. On the 2026-07-28 era:

- `resultType: "input_required"` tool results are inspected. Each `inputRequests` entry is gated with the same policy methods as legacy server requests (`sampling/createMessage`, `elicitation/create`, `roots/list`). Denied requests turn the result into a tool error. Sensitive form fields are denied; URL-mode elicitation URLs receive allowlist and taint checks. Prompt/resource handlers currently scan their content but do not run input-required inspection.
- The client's retry `inputResponses` are taint-matched like sink arguments.
- `notifications/tools/list_changed` is forwarded to the client and triggers a proxy-side `tools/list` re-lock: the synthetic response is compared against `palizade.lock`, drifted metadata is approval-gated, and the synthetic response is never forwarded.
- `server/discover` strings are scanned; a top-level `tools` array is also lock-checked like `tools/list`. Other discover result shapes receive metadata scanning without tool hashing.
- `subscriptions/listen` responses are scanned through the generic content path.
- `structuredContent` is scanned and taint-registered like text content. Spotlighting changes string fields and preserves non-string fields, but can exceed a schema's string length constraint. List `ttlMs`/`cacheScope` are audited; lock verification runs on every refresh.

## Native Client Tool Hooks

`packages/core/src/hooks.ts` brings native client tools (Claude Code Bash/Read/Write/Edit/WebFetch, Cursor shell and MCP execution, Codex shell/apply_patch) under the same engine as the proxy.

- `normalizeNativeEvent` maps hook JSON to synthetic tool events. Bash/Shell carry commands, extracted destinations/redirects and suspicious constructs; Write/Edit carry paths/content; WebFetch carries a URL. Read/WebFetch/Grep/Glob responses register provenance in the same SQLite store. Native hook security state is keyed by profile plus the client's session ID, independently of taint scope and `PALIZADE_RUN_ID`. Profile-scoped taint records remain shared across client sessions. Hooks without a session ID use the shared `native-session` fallback; provide `--session` when the client omits it.
- Decisions map to each client's output format: Claude Code/Codex `hookSpecificOutput.permissionDecision` (deny/ask), Cursor `permission` (deny/ask). `require_approval` policy decisions become "ask" so the client's own approval flow decides.
- Hooks fail closed by default (`hooks.failMode: closed`, `hooks.timeoutMs`, `hooks.maxInputBytes`): errors anywhere in the CLI action, including config loading, oversized input, malformed JSON and evaluation/timeout, print the client's deny decision and exit 2. Errors before a valid config is loaded default to closed. Error output uses a generic message to avoid exposing input or credentials. Explicit fail-open applies after successful config loading.
- `palizade install-hooks <client>` merges hook entries into `~/.claude/settings.json`, `~/.cursor/hooks.json` (`failClosed: true`), or `~/.codex/hooks.json`, backing up and refusing to overwrite malformed JSON.
- Prompt hooks (`UserPromptSubmit` in Claude Code and Codex, `beforeSubmitPrompt` in Cursor) record destination shaped values from the user's prompt (`extractStatedObservables`: email addresses, exact urls and their hosts, bare hosts, @handles and #channels, IBAN or account style numbers, phone numbers) as HMACs in `user_statements`, keyed by taint scope, for `taint.userIntent.ttlMs`. Before sink matching, `maskStatedObservables` blanks those values in each argument, so a user stated destination does not count as copied from untrusted content; nothing else in the argument is exempt. A url is blanked only when the exact url was stated. Prompt hooks never block the prompt, whatever fails.
- MCP tools seen through hooks (`mcp__<server>__<tool>` in Claude Code and Codex, the config key Cursor sends in `command`) are checked by an engine for that server when Palizade does not wrap it: trust `hooks.mcpTrust` (untrusted by default), identity from the client's own config so the catalog applies. Servers in `palizade.yaml`, or whose client entry is a Palizade wrapper, are left to their proxy.
- Shell parsing is intentionally heuristic (`analyzeShellCommand`): URLs, host-looking tokens after network verbs, `>`/`<` redirect targets, and suspicious constructs (`$(...)`, backticks, `eval`, base64 pipelines, `/dev/tcp`). It is not a shell parser.

## Sandboxed Launch

`packages/core/src/sandbox.ts` turns `servers.<name>.sandbox` into a launch plan; `packages/core/src/launch.ts` is the only place stdio upstreams are spawned (`wrap`, `lock approve`, `lock diff`). `none` (default) keeps the old behavior. Validation runs before any spawn: on Windows only `docker` is accepted, `bubblewrap` needs Linux and `seatbelt` needs macOS, and a `url` server with a sandbox is a config error.

- `docker`: `run --rm -i --init --security-opt no-new-privileges --cap-drop ALL --read-only --tmpfs /tmp --pids-limit 512`, the server `cwd` bind-mounted read-only at `/workspace`, `writable` paths bind-mounted read-write (`host` or `host::/container`), `HOME=/tmp`. Environment is never copied from the host: only `env` from `palizade.yaml` and `passEnv` names are passed, as `-e NAME` so values never appear in the argument list.
- `bubblewrap`: `--unshare-all --die-with-parent --new-session --cap-drop ALL`, system directories read-only, `cwd` read-only, `writable` paths bound read-write, filtered environment.
- `seatbelt`: `sandbox-exec -p <profile>` that denies writes outside `writable` and `/tmp`, and denies network unless allowlisted.
- `network: none` (default for sandboxed servers) removes networking. `network: allowlist` with `allowHosts` starts a per-launch HTTP/CONNECT egress proxy (`packages/core/src/egress-proxy.ts`): exact hosts or `*.suffix`, at most 64 connections, 120 s idle timeout, and a random proxy credential; every allow/deny is audited as `sandbox/egress`. The allowlist is only enforced when the server cannot route around the proxy: seatbelt, or docker with `dockerNetwork` naming an internal network whose only route is the proxy. Docker without `dockerNetwork`, and bubblewrap (which shares the host network), are rejected at config load unless `advisoryNetwork: true` is set, and `doctor` labels those servers ADVISORY.
- Every spawn is audited (`process/spawn`, action `log_only`) with the full command and arguments, secrets masked, environment as key names only. If the audit write fails the spawn is refused. `palizade doctor` lists unsandboxed servers and fails on an unsupported sandbox.

## Tool Classification

The coding preset checks Git pushes by resolving simple literal remotes with local `git remote get-url --push --all`, under a one-second/4096-byte bound. It makes no network call. Dynamic, compound or unsupported command forms require approval. Shell network command detection is deliberately conservative, not a complete shell parser.

The research preset checks every normalized/canonical file target against one configured output directory. It blocks critical paths even inside that directory, and rejects tools with network, remote-write, memory, execution or deletion capabilities. Source overrides remain an administrator trust decision.

Tool list detections are decided per tool: a flagged description withholds that tool only, and the heuristic detector gives tool directions ("use this tool when") and imperative density little weight on the `tool_description` surface, since real descriptions are written that way. Catalog rules may set `ignoreDestructiveHint` for read tools a known server marks destructive (Notion's POST searches).

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

Sink attempts (including denied attempts) update shared session counters atomically. The rolling minute stores timestamps; distinct destinations and repeated tool/argument signatures are HMACs in SQLite. Tracking is bounded by `limits.historyEntries` (1000); exhaustion gates further sinks rather than dropping evidence. Repeats and destination counts use a sliding window (`limits.windowMs`, 10 minutes), and call-rate timestamps expire after one minute. Only outbound sink calls feed these gates: calls with a destination, or with `sends_message`, `writes_remote`, `deletes_data` or `persists_memory`.

A sink call whose only untrusted data is one or more urls copied exactly as an untrusted record wrote them (`verbatimToken` finds the url as a whole token in an untrusted record), into a tool with only `network_egress` and `reads_untrusted_content`, with no sensitive taint, secret or personal data detection, split match or other tainted text, sets `copied_link_only`. Presets other than strict allow it outside Rule of Two, quarantine and rate limits.

High-score source/tool responses (default 0.85) and hard blocks on tainted/split/lookalike destinations start shared quarantine. It expires after `taint.quarantine.turns` (20 sink attempts) or `ttlMs` (1800000), whichever occurs first. Start/end/clear events are audited separately. Session destination grants do not suppress quarantine. Expiry is evaluated on the next sink attempt.

Session flags `seenUntrusted` and `seenSensitive` persist in SQLite. Wrapper flags follow the configured session scope; profile mode shares one logical session across wrapped processes, while `PALIZADE_RUN_ID` isolates profile plus run ID. Native hooks instead key state by profile plus client session ID. Exposure flags expire together after `taint.exposure.ttlMs` (7200000 by default), refreshed on each new untrusted or sensitive exposure; sink calls do not refresh them. Expiry is applied before the next source exposure or sink decision and displayed by status. Pre-TTL rows receive one bounded grace period when first used. Expiry preserves quarantine, grants, counters and taint records. `palizade session reset` explicitly clears all session state, preserving taint records; `--session` selects a native client session, otherwise the configured wrapper scope is reset. Session destination grants are bounded to 1024 HMACs and never bypass hard blocks.

Outbound sink calls keep a memory-only rolling payload window for each session and destination. `taint.window` defaults to 12 calls, 900000 ms TTL, 262144 bytes per window and 256 destinations. Body fields and URL query values are concatenated, decoded and matched; only sensitive records gain eight-character shard fingerprints, HMAC-protected in SQLite. Window matches exclude temporal-only hits. The window is process-local and cannot correlate shards across wrapper/hook processes.

Learned egress grants live in the separate `egress.learnedFile` (default `palizade.allow.yaml`, relative to config). It is validated at startup and before each sink call. Remember writes use an exclusive lock and atomic replacement; lock contention fails closed. Hard policy blocks always win over egress approvals. Source-call destinations are not egress-gated.

Sink fields and the flattened argument text are expanded into bounded decoded candidates before matching both taint classes. Original payloads are retained, and ingestion never decodes. `taint.decode.maxDepth` defaults to 2 and `maxBytes` to 262144 total decoded bytes; exceeding the budget follows policy `on_error`. Supported views include base64/base64url, hex, percent encoding, common HTML entities, JS escapes, UTF-8 RFC 2047 B/Q and punycode. Audit `matchReasons` records `decoded:<kind>` without payloads.

Matching strips TAG characters, variation selectors, soft hyphens and invisible operators in a separate view. Display content stays unchanged unless policy sanitizes it. Common Cyrillic/Greek lookalikes and fullwidth forms are folded only for domain and identifier tokens; prose is not folded. Host tokens include ASCII and skeleton views. The heuristic detector scans the stripped view with original span offsets and reports `hidden_unicode` counts and escaped code points.

Runtime taint uses `.palizade/taint.sqlite` by default. The store scope defaults to `profile`, so separate wrapped processes using the same profile can match observable taint until TTL expiry. `PALIZADE_RUN_ID` enables stronger host-provided run correlation. Raw exact fragments and tokens are HMAC-protected with `.palizade/taint.key`; SimHash is retained for fuzzy comparison.

Taint records carry classes. Existing records default to `untrusted`; new sensitive records use the same exact, token, fuzzy, TTL, and SQLite machinery. A value can be both `untrusted` and `sensitive`, which is how a fetched secret can later be blocked at an egress sink without a second detector hit.

Sensitive origins can be declared per server, per tool, or by path-pattern hints in `palizade.yaml`. This is useful for tools like secrets managers where the output is sensitive by provenance even if it does not match a built-in pattern.

## Audit

Audit events include identity/scope, tool/method, provenance IDs, detector labels, rule/action/reason, latency, payload hash and a hash chain. Egress metadata includes classes, roles, redaction and destination status, with copied destinations masked. Raw capture is off by default; captured payloads with observable taint are replaced by a redaction marker, and other captured text receives known-secret/PII masking. The chain is tamper-evident only while logs are protected.

## Simplifications

- Stdio and Streamable HTTP are both implemented; the transparent listener shares one upstream session per served server (use the stdio bridge for per-client legacy sessions).
- Optional model support is externally configured and must pass `palizade detectors verify` before being described as active.
- Secret and PII detection is pattern-based and high-precision by design; custom, transformed, split, or obfuscated secrets can be missed. Egress allowlists and taint/provenance rules are the structural controls.
- Fuzzy matching is lightweight SimHash, not semantic equivalence.
- Prompt Guard 2 is opt-in because downloading the model during every `init` would make the default DX heavy.
