export const DEFAULT_CONFIG = `stateDir: .palizade
policy: policies/default.yaml
lockfile: palizade.lock

audit:
  jsonl: .palizade/audit.jsonl
  sqlite: .palizade/audit.sqlite
  captureRawPayloads: false

approvals:
  mode: localhost
  timeoutMs: 30000
  default: deny

detectors:
  heuristic: true
  promptGuard2:
    enabled: false
    model: sinatras/Llama-Prompt-Guard-2-86M-ONNX
    cacheDir: .palizade/models
    device: cpu

transport:
  maxMessageBytes: 67108864
  maxBufferedBytes: 67108864
  allowBatches: false
  allowContentLength: false

taint:
  sqlite: .palizade/taint.sqlite
  keyPath: .palizade/taint.key
  scope: profile
  profileId: default
  ttlMs: 86400000
  suspiciousScore: 0.35
  fuzzyHammingMax: 7
  temporal:
    enabled: true
    turns: 3
    ttlMs: 300000
    detectorScoreGte: 0.55

servers:
  toy:
    command: node
    args:
      - examples/toy-mcp-server/server.mjs
    trust: untrusted
    toolClasses:
      read_web: source
      send_email: sink
      echo: pure
  filesystem:
    command: node
    args:
      - node_modules/@modelcontextprotocol/server-filesystem/dist/index.js
      - .
    trust: semi
    toolClasses:
      read_file: source
      read_text_file: source
      read_media_file: source
      read_multiple_files: source
      list_directory: source
      list_directory_with_sizes: source
      directory_tree: source
      search_files: source
      get_file_info: source
      list_allowed_directories: source
      write_file: sink
      edit_file: sink
      create_directory: sink
      move_file: sink
`;

export const DEFAULT_POLICY = `version: 1
defaults:
  action: allow
  on_error: block

rules:
  - id: deny-server-sampling
    name: Deny server-initiated model access
    when:
      direction: request
      method: sampling/createMessage
    action: block
    reason: MCP server attempted to access the model through sampling.

  - id: block-poisoned-tool-metadata
    name: Block poisoned tool metadata
    when:
      direction: response
      method: tools/list
      detector_score_gte: 0.75
    action: block
    reason: Tool metadata looks like prompt injection or tool poisoning.

  - id: block-untrusted-unknown-tool
    name: Block unknown tools on untrusted servers
    when:
      direction: request
      method: tools/call
      trust: untrusted
      tool_class: unknown
    action: block
    reason: Unknown tools on untrusted servers must be classified explicitly.

  - id: approve-semi-unknown-tool
    name: Require approval for unknown tools on semi-trusted servers
    when:
      direction: request
      method: tools/call
      trust: semi
      tool_class: unknown
    action: require_approval
    reason: Unknown tools on semi-trusted servers require approval.

  - id: log-trusted-unknown-tool
    name: Audit unknown tools on trusted servers
    when:
      direction: request
      method: tools/call
      trust: trusted
      tool_class: unknown
    action: log_only
    reason: Unknown tool on trusted server allowed with audit logging.

  - id: log-unapproved-tool-metadata
    name: Surface tool lock drift
    when:
      direction: response
      method: tools/list
      lock_status:
        - missing
        - new
        - changed
    action: log_only
    reason: Tool metadata is not approved in palizade.lock.

  - id: sanitize-suspicious-untrusted-output
    name: Spotlight suspicious untrusted output
    when:
      direction: response
      method: tools/call
      trust: untrusted
      detector_score_gte: 0.35
    action: sanitize
    reason: Untrusted tool output contains injection-like signals.

  - id: sanitize-suspicious-resource-content
    name: Spotlight suspicious resource content
    when:
      direction: response
      method:
        - resources/read
        - prompts/get
      detector_score_gte: 0.35
    action: sanitize
    reason: Resource or prompt content contains injection-like signals.

  - id: block-tainted-sink
    name: Block tainted content entering sinks
    when:
      direction: request
      method: tools/call
      tool_class: sink
      taint: true
    action: block
    reason: Tainted content is flowing into a sink tool.

  - id: block-tainted-egress-destination
    name: Block tainted outbound destinations
    when:
      direction: request
      method: tools/call
      capabilities_any:
        - network_egress
        - sends_message
      tainted_argument_role_any:
        - url
        - hostname
        - email_recipient
        - http_query
    action: block
    reason: Tainted content is being used as an outbound destination or query parameter.

  - id: require-approval-temporal-taint-sink
    name: Require approval during temporal taint
    when:
      direction: request
      method: tools/call
      tool_class: sink
      temporal_taint: true
    action: require_approval
    reason: Recent suspicious untrusted content makes sink calls risky.
`;
