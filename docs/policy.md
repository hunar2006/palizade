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
- `temporal_taint`: boolean
- `detector_score_gte`: number from `0` to `1`
- `detector_score_lt`: number from `0` to `1`
- `labels_any`: detector labels
- `lock_status`: `approved`, `new`, `changed`, `missing`, or `unknown`
- `argument_regex`: JavaScript regular expression applied to flattened arguments
- `argument_role_any`: roles found in outgoing arguments, such as `url`, `email_recipient`, `file_path`, `shell_command`, or `http_query`
- `tainted_argument_role_any`: argument roles where taint matched

## Actions

- `allow`: forward unchanged.
- `block`: return a JSON-RPC error instead of forwarding.
- `sanitize`: wrap untrusted content in spotlighting markers.
- `redact_spans`: replace detector spans with `[REDACTED:<label>]`.
- `require_approval`: ask the configured approval provider.
- `log_only`: forward but emit an audit event.

## Default Unknown Tool Behavior

- Untrusted server plus unknown tool: block.
- Semi-trusted server plus unknown tool: require approval.
- Trusted server plus unknown tool: allow with audit logging.
- Policy evaluation errors: block in enforcing presets.

## Shipped Presets

- `policies/audit-only.yaml`: observe suspicious content and risky flows without enforcement.
- `policies/default.yaml`: enforce taint-to-sink blocking while allowing classified normal use.
- `policies/research-read-only.yaml`: for agents that gather web, file, resource, or prompt content and should not write, delete, execute shell/code, send messages/email, publish remotely, access credentials, or call unclassified tools.
- `policies/strict.yaml`: require approval or explicit allowance for most activity.
