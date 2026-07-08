# Policy Reference

Policy files are YAML documents with `version: 1`, `defaults`, and ordered `rules`.

Rules use first-match-wins semantics. If no rule matches, `defaults.action` is used. If policy evaluation throws, `defaults.on_error` is used.

## Match Fields

- `direction`: `request` or `response`
- `method`: JSON-RPC method such as `tools/call`
- `server`: configured server name
- `tool`: MCP tool name
- `tool_class`: `source`, `sink`, `pure`, or `unknown`
- `capabilities_any`: any matching capability flag
- `capabilities_all`: every listed capability flag
- `trust`: `trusted`, `semi`, or `untrusted`
- `taint`: boolean
- `sensitive_taint`: boolean, true when an argument contains taint classed as sensitive
- `temporal_taint`: boolean
- `secret_detected`: boolean, true when outbound arguments contain a `secret:*` detector label
- `pii_detected`: boolean, true when outbound arguments contain a `pii:*` detector label
- `destination_allowed`: boolean, false when an allowlist is configured and a URL/host/email destination is outside it
- `destination_allowlist_configured`: boolean, true only when `egress.allowlist.hosts` or `egress.allowlist.emails` has entries
- `detector_score_gte`: number from `0` to `1`
- `detector_score_lt`: number from `0` to `1`
- `labels_any`: detector labels
- `lock_status`: `approved`, `new`, `changed`, `missing`, or `unknown`
- `argument_regex`: JavaScript regular expression applied to flattened arguments
- `argument_role_any`: roles found in outgoing arguments, such as `url`, `email_recipient`, `file_path`, `shell_command`, or `http_query`
- `tainted_argument_role_any`: argument roles where taint matched

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

- `policies/audit-only.yaml`: log suspicious metadata, tainted sinks, resource/prompt injection, and sampling without enforcement.
- `policies/interactive.yaml`: same posture as `default`, except `block-tainted-sink` uses `require_approval`. Choose this when legitimate user-authorized writes of tainted content should be possible after confirmation.
- `policies/default.yaml`: hard-blocks tainted content entering sink tools while keeping suspicious output sanitized.
- `policies/egress.yaml`: opt-in preset that adds secret/PII outbound controls and destination allowlists.
- `policies/strict.yaml`: strictest preset; blocks lock drift, suspicious output, unknown tools, tainted sinks, and secret egress.

Which preset should I use? Start with `audit-only` to learn your traffic. Use `interactive` for desktop/operator workflows where a human can confirm risky writes. Use `default` for unattended agents where tainted sink calls should not have an escape hatch. Use `egress` or `strict` when protecting secrets and destinations is part of the goal.

## Egress Preset

`policies/egress.yaml` is opt-in. It keeps the default prompt-injection and taint protections, then adds:

- `block-secret-egress`: sensitive-class taint entering egress tools is blocked.
- `block-secret-detected-egress`: directly detected secrets in outbound arguments are blocked even if they were not previously tainted.
- `block-sensitive-into-untrusted-destination`: tainted sink calls are blocked when URL, host, or email destinations are outside `egress.allowlist`.
- `allow-tainted-allowed-egress-destination`: lets tainted network/message egress proceed only when an allowlist is configured and the destination matches it.
- `redact-pii-egress`: detected PII in message/network egress is redacted before forwarding.

The allowlist rule is structural: with an allowlist configured, tainted data must flow only to allowed hosts/domains/emails. Secret and PII detection is pattern-based and intentionally high precision; it can miss custom or obfuscated secrets.

## Default Unknown Tool Behavior

- Untrusted server plus unknown tool: block.
- Semi-trusted server plus unknown tool: require approval.
- Trusted server plus unknown tool: allow with audit logging.
- Policy evaluation errors: block in enforcing presets.

## Detector Defaults

Detector-based response rules are trust-agnostic in the shipped presets. Semi-trusted servers such as filesystem and fetch still have suspicious `tools/call` output spotlighted or escalated when detector scores cross policy thresholds. Trust affects unknown-tool handling and taint registration, but it does not suppress detector-score rules by default.

Secret and PII detectors are disabled in the default config surface until explicitly enabled. `policies/default.yaml` does not add egress-blocking behavior; use `policies/egress.yaml` or `policies/strict.yaml` when you want secret/PII egress enforcement.
