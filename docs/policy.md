# Policy Reference

Policy files are YAML documents with `version: 1`, `defaults`, and ordered `rules`.

Rules use first-match-wins semantics. If no rule matches, `defaults.action` is used. If policy evaluation throws, `defaults.on_error` is used. Shipped presets place specific hard blocks ahead of gates and generic rules. Tainted-memory approval and allowlisted egress are explicit exceptions to the generic copied-content block; neither overrides a destination, secret, split or critical-target hard block. Egress allow/redaction exceptions cannot bypass critical-path, temporal, quarantine, rate or loop gates.

Run `palizade policy check [file]` before deploying a policy. It reports schema errors and unknown keys with the YAML path, line and a fix hint; rules after a catch-all (a rule with no `when`, an empty `when`, or only `direction: [request, response]`); conditions that never match (an empty list such as `labels_any: []`, `detector_score_gte` at or above `detector_score_lt`, `detector_score_lt: 0`); an invalid `argument_regex`, which would send every evaluation to `on_error`; duplicate rule ids; and `server` or `tool` values that are not in `palizade.yaml` or `palizade.lock`. Edited policies are hot reloaded by running processes; an invalid edit keeps the previous policy.

## Match Fields

The `persists_memory` capability marks entity/observation/relation, remember/note and vector/upsert writes. Tainted memory writes require approval in default, interactive and egress; strict blocks them. Rule of Two includes this capability. Hard destination/secret blocks remain ahead of memory approval.

- `critical_path`: a logical or symlink-resolved file argument matches a built-in/configured protected target or cannot be resolved safely. Enforcing presets require approval for writes; strict blocks tainted critical writes.
- `argument_path_glob`: any configured glob matches a normalized logical/canonical argument path. Relative patterns match at any directory depth; `~` expands to the current user's home.
- `output_path_allowed`: every file argument resolves within `protectedTargets.outputDirectory`; used by the research preset. Symlink/traversal escapes are excluded.
- `git_push_unapproved`: a Git push targets a remote outside configured/learned allowlists, or its remote cannot be resolved safely. The coding preset requires approval.

- `rate_limited`: per-minute sink attempts exceed `limits.sinkCallsPerMinute` (60), session destinations exceed `distinctDestinations` (20), or bounded history overflows.
- `loop_detected`: an identical tool/argument HMAC repeats more than `limits.repeatThreshold` (5) times in the session. Enforcing presets require approval for these gates.

- `session_quarantined`: shared session quarantine remains within both TTL and turn bounds. Every enforcing preset requires approval for sinks after hard blocks.

- `session_untrusted`: session has seen untrusted or suspicious content within the exposure lifetime. The enforcing presets use it to ask before deleting data after such exposure.
- `rule_of_two`: session has seen both untrusted/suspicious and sensitive content within the exposure lifetime (`taint.exposure.ttlMs`, default two hours, refreshed on each exposure); default, strict and interactive approval-gate network, message and remote-write sinks even for paraphrased arguments. Native hook session flags are isolated by client session ID; taint records retain their configured scope. Specific hard blocks run first.
- `destination_session_trusted`: every destination has an explicit session grant. This suppresses only the Rule of Two gate and approve-new mode, not hard blocks.

- `split_match`: the destination's recent outbound window matches observable taint that is absent from the current call. Default requires approval; strict and egress block.

- `new_destination`: a destination is absent from configured and learned allowlists, including IDs. Strict mode blocks it.

- `tainted_destination`: untrusted observable taint matched a URL, host, mail recipient, repository, channel or account ID after matching normalization/decoding. Temporal taint alone does not set this flag. Destinations the user typed in a prompt are left out of this check (see `user_stated_destination`).
- `copied_link_only`: the only untrusted data in the call is one or more urls copied exactly as an untrusted source wrote them (a search result, a link in a page), into a tool that only reads (`network_egress` and `reads_untrusted_content`, nothing that writes, sends or runs code), with no sensitive data, secrets or personal data detected and no split match. Following such a link reads more untrusted content but leaks nothing the page's author did not already have. A url with anything added, such as a query built from page or session data, does not count. The default, interactive and coding agent presets allow it (`allow-following-copied-link`) unless the session is under Rule of Two, quarantine, rate or loop limits; strict does not.
- `tool_metadata_taint`: an argument matches text from a tool description of a server that is not trusted (recorded when `taint.toolMetadata` is on). Poisoned descriptions work by telling the model to call other tools with values they supply, so the default, interactive, strict and coding agent presets ask first (`approve-arguments-from-tool-descriptions`).
- `user_stated_destination`: the call names at least one destination (email address, exact url, host, @handle or #channel, account or IBAN style number, phone number) that the user typed in a recent prompt. Palizade learns these from the prompt hooks (`UserPromptSubmit` in Claude Code and Codex, `beforeSubmitPrompt` in Cursor). Such values are not counted as copied from untrusted content, since the user asked for them; the rest of the call is checked as usual. Turn this off with `taint.userIntent.enabled: false`; statements expire after `taint.userIntent.ttlMs` (2 hours by default). A stated host does not vouch for a different url on that host.
- `lookalike_destination`: a Unicode/punycode host skeleton collides with an allowlisted or untrusted-tainted host. Matching does not authorize the lookalike host.

- `direction`: `request` or `response`
- `method`: JSON-RPC method such as `tools/call`
- `server`: configured server name
- `tool`: MCP tool name
- `tool_class`: `source`, `sink`, `pure`, or `unknown`
- `capabilities_any`: any matching capability flag
- `capabilities_all`: every listed capability flag
- `trust`: `trusted`, `semi`, or `untrusted`
- `taint`: boolean, observable copied content matched; temporal-only evidence uses `temporal_taint` separately
- `sensitive_taint`: boolean, true when an argument contains taint classed as sensitive
- `temporal_taint`: boolean
- `secret_detected`: boolean, true when outbound arguments contain a `secret:*` detector label
- `pii_detected`: boolean, true when outbound arguments contain a `pii:*` detector label
- `destination_allowed`: boolean, false when a configured host/email/typed-ID allowlist excludes any destination
- `destination_allowlist_configured`: boolean, true when `egress.allowlist.hosts`, `emails` or `destinations` has entries
- `detector_score_gte`: number from `0` to `1`
- `detector_score_lt`: number from `0` to `1`
- `labels_any`: detector labels
- `lock_status`: `approved`, `new`, `changed`, `missing`, or `unknown`
- `argument_regex`: JavaScript regular expression applied to flattened arguments
- `argument_role_any`: roles found in outgoing arguments, such as `url`, `email_recipient`, `file_path`, `shell_command`, or `http_query`
- `tainted_argument_role_any`: argument roles where taint matched
- `tool_shadowing_detected`: boolean, set on `tools/list` (per tool), prompt/resource lists and `server/discover` when metadata names an exact tool that belongs to a different wrapped server (for example `github.create_issue`, or a compound name such as `create_issue`; plain words such as `search` are ignored)
- `name_collision_detected`: boolean, set per tool on `tools/list` when another wrapped server in the same state directory already exposes the same tool name
- `hidden_unicode_detected`: boolean, set when descriptions, titles, schema property names, descriptions, `default`, `enum`, `examples` or `const` contain Unicode TAG characters, variation selectors, soft hyphens, zero width or bidi controls outside valid emoji sequences

On `tools/list`, the three metadata conditions are evaluated once per flagged tool with `tool` set to that tool's name. `block` removes the tool from the list returned to the client and blocks later `tools/call` requests for it; `sanitize` strips hidden characters from that tool; `require_approval` asks first. The enforcing presets block collisions and shadowing and sanitize hidden Unicode. Tools that reuse well known built in names (`metadata.builtinNames`, default `read_file`, `write_file`, `bash`, `fetch`) get the detector label `builtin_tool_name` but are not blocked, because the reference filesystem and fetch servers legitimately use those names. Dangerous schema defaults such as `--no-sandbox`, `--dangerously-skip-permissions`, `--yolo` or `autoApprove: true` get the label `dangerous_default` and raise the tool's detector score to 0.4, which spotlights its description under the default presets.

## Actions

- `allow`: forward unchanged.
- `block`: for `tools/call` requests, return a CallToolResult-style payload with `isError: true`; protocol-level blocks still return JSON-RPC errors.
- `sanitize`: wrap untrusted content in spotlighting markers.
- `redact_spans`: replace detector spans with `[REDACTED:<label>]`.
- `redact_secrets`: replace detected secret/PII spans in outbound arguments with `[REDACTED:<label>]` and forward.
- `require_approval`: ask the configured approval provider.
- `log_only`: forward but emit an audit event.

Set `audit.errorVerbosity: false` to make client-facing tool-call block messages opaque. The default `true` includes the matched rule id and human reason so MCP clients and models can tell that Palizade blocked the call, rather than guessing that the upstream tool failed.

For headless desktop clients, prefer `approvals.mode: localhost`. It serves a persistent loopback approval inbox at `http://127.0.0.1:32145/` by default, attempts to open the one-time approval page in the default browser, writes the current approval URL to `.palizade/pending-approval.url`, and includes that inbox/file hint in the client-facing tool error if the request times out or is denied. If the fixed port is already occupied by another Palizade process, localhost mode falls back to an ephemeral port and writes the actual URL to the same file and client-facing hint. `approvals.openBrowser: false` disables browser launch while keeping the inbox and URL file.

## Preset Spectrum

`coding-agent` adds tainted critical-write and shell blocks, sensitive/Rule-of-Two network shell blocks (including DNS and ICMP), and approval for unallowlisted Git pushes to the default rules. `research-readonly` permits sources and local output writes within `protectedTargets.outputDirectory`; it blocks other sinks, unknown tools and critical targets. Explicit source classification is needed for read tools whose names imply network writes. These presets are opt-in.

- `policies/audit-only.yaml`: log suspicious metadata, tainted sinks, resource/prompt injection, and sampling without enforcement.
- `policies/interactive.yaml`: same posture as `default`, except `block-tainted-sink` uses `require_approval`. Choose this when legitimate user-authorized writes of tainted content should be possible after confirmation.
- `policies/default.yaml`: hard-blocks copied content entering general sink tools, with explicit approval for tainted memory persistence; suspicious output is sanitized.
- `policies/strict.yaml`: strictest preset; blocks lock drift, suspicious output, unknown tools, tainted sinks, and secret egress.
- `policies/egress.yaml`: opt-in preset that keeps the default prompt-injection and taint posture, then adds secret/PII outbound controls and destination allowlists.

Start with `audit-only` to observe traffic. Use `interactive` when a human should confirm legitimate copied-content writes, `default` for hard blocks on general copied-content sinks, `strict` for tighter output/metadata/egress controls, or `egress` for secret/PII controls. `coding-agent` adds shell protection; `research-readonly` confines side effects to the output directory. Research output still requires approval while quarantine, rate or loop gates are active. Strict blocks suspicious output at every score above its threshold, including strong injection that formerly reached an earlier sanitization rule.

`egress.mode` defaults to `open`. With `approve_new`, destinations outside configured/learned allowlists require approval; allow always writes the separate `egress.learnedFile`. `allowlist_only` blocks them, and the strict preset blocks new destinations regardless of mode. Default users can opt into `approve_new`. Explicit session grants suppress only Rule of Two and approve-new, never hard blocks or other session gates.

## Egress Preset

`policies/egress.yaml` is opt-in. It keeps the default prompt-injection and taint protections, then adds:

- `block-secret-egress`: sensitive-class taint entering egress tools is blocked.
- `block-secret-detected-egress`: directly detected secrets in outbound arguments are blocked even if they were not previously tainted.
- `block-sensitive-into-untrusted-destination`: tainted sink calls are blocked when URL, host, or email destinations are outside `egress.allowlist`.
- `allow-tainted-allowed-egress-destination`: permits copied network/message content only to configured destinations, with no active critical/temporal/quarantine/rate/loop gate; detected PII takes the guarded redaction path instead.
- `redact-pii-egress`: detected PII in message/network egress is redacted before forwarding.

The allowlist rule is structural: with an allowlist configured, tainted data must flow only to allowed hosts/domains/emails. Secret and PII detection is pattern-based and intentionally high precision; it can miss custom, transformed, split, or obfuscated secrets.

## Server Input Requests (2026-07-28 MRTR)

Servers on the 2026-07-28 protocol request sampling, elicitation, and roots inside tool results (`resultType: "input_required"`). Palizade gates each request with the same policy methods the legacy server-initiated requests used:

- `sampling/createMessage` requests are matched by the existing `deny-server-sampling` rule (block in `default`, `strict`, `interactive`, `egress`).
- `elicitation/create` requests require approval in every enforcing preset. Form-mode elicitations that request sensitive fields (passwords, API keys, tokens, payment data) are denied regardless of policy. URL-mode elicitation URLs are checked against the egress allowlist and taint records.
- `roots/list` requests pass through like the legacy safe list.

The client's retry `inputResponses` are checked for observable tainted or sensitive content like sink arguments. Input-required inspection currently applies to `tools/call` results; prompt/resource input-required results do not enter that handler. See the integration report for the lane-reported protocol limits.

## Default Unknown Tool Behavior

- Untrusted server plus unknown tool: block.
- Semi-trusted server plus unknown tool: require approval.
- Trusted server plus unknown tool: allow with audit logging.
- Policy evaluation errors: block in enforcing presets.

## Testing A Policy

Write test cases in YAML: each case gives the decision context Palizade would build and the action or rule you expect. Unknown context fields are errors, so a typo cannot pass by accident.

```yaml
policy: ../default.yaml          # relative to this file; or pass --policy, or use palizade.yaml's policy
cases:
  - name: a destination copied from untrusted content is blocked
    context: { direction: request, method: tools/call, tool_class: sink, tainted_destination: true }
    expect: { action: block, rule: block-tainted-destination }
  - name: a clean read is allowed
    context: { direction: request, method: tools/call, tool_class: source }
    expect: allow
```

Run them with `palizade policy test my-policy.test.yaml`; it exits non zero on any failure, so it fits in CI. The shipped presets have their own cases in `policies/tests`, which run with the test suite.

## How Tools Are Classified

Each tool gets a class (`source`, `sink`, `pure` or `unknown`) and a set of capabilities. The first of these that applies wins:

1. `toolClasses` and `toolCapabilities` in `palizade.yaml`.
2. The built-in catalog, for servers you configured from a known package, image or url (filesystem, fetch, memory, git, GitHub, Slack, Puppeteer, Playwright, Brave Search, time, sequential thinking). Run `palizade tools --catalog` for the list. Set `catalog: <id>` on a server to use an entry for a custom build, or `catalog: false` to turn it off. Tools the catalog does not name fall through to the next steps.
3. Annotations. On untrusted and semi trusted servers they can only raise risk: `destructiveHint` or `openWorldHint` makes a tool a sink, `readOnlyHint` is ignored.
4. Heuristics on the tool name, the input schema and the description. Property names such as `to`, `cmd`, `webhook_url`, `amount`, or a path plus content pair add sink capabilities. On servers that are not trusted, the description and title can add sink capabilities but cannot make a tool a source, since that text comes from the server.

`palizade tools [server]` prints the class, capabilities and reasons for every locked tool without starting any server. Audit events record the same reasons under `metadata.classificationReasons`.

## Detector Defaults

Detector-based response rules are trust-agnostic in the shipped presets. Semi-trusted servers such as filesystem and fetch still have suspicious `tools/call` output spotlighted or escalated when detector scores cross policy thresholds. Trust affects unknown-tool handling and taint registration, but it does not suppress detector-score rules by default.

Secret and PII detectors remain disabled until explicitly enabled. Default blocks untrusted destinations and uses session/egress-mode gates, but does not add direct secret/PII egress blocks; use `egress` or `strict` for those rules.
