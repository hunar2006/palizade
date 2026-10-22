# Palizade

**An MCP-native dataflow firewall for AI agents.**

_iptables for agentic tool use._

Agents often treat web pages, emails, files, tickets, and tool output as if they were trusted instructions. A hidden prompt injection in that content can then steer the agent into sending email, writing files, deleting data, or making network calls. Palizade sits between an MCP client and its MCP servers, tracks where data came from, and stops untrusted data from driving sensitive actions.

Runs locally on Windows, macOS and Linux. Requires Node.js 22.13 or newer.

## Get Started

Install it globally, so the path written into your client config stays valid (an `npx` cache can be cleared):

```bash
npm install -g palizade
palizade init                      # writes palizade.yaml and a default policy here
```

Then pick your client. Each `install-config --all` run rewrites the client's MCP entries to go through Palizade, copies the original servers into `palizade.yaml` as `trust: untrusted`, and keeps a `.bak` of the client file. Add `--dry-run` first to see the change.

**Claude Desktop**

```bash
palizade install-config --all
```

Fully quit and reopen Claude Desktop.

**Claude Code**

```bash
palizade install-config --all --client claude-code             # user servers in ~/.claude.json
palizade install-config --all --client claude-code --project   # this repo's .mcp.json
palizade install-hooks claude-code                             # also cover Bash, Read, Write, WebFetch
```

Servers added with plain `claude mcp add` use the local scope, which belongs to one directory. Run this from that directory to wrap them:

```bash
palizade install-config --all --client claude-code --local
```

Close Claude Code before running these, since it also writes `~/.claude.json`.

**Cursor**

```bash
palizade install-config --all --client cursor             # ~/.cursor/mcp.json
palizade install-config --all --client cursor --project   # this repo's .cursor/mcp.json
palizade install-hooks cursor
```

**Codex**

```bash
palizade install-config --all --client codex             # ~/.codex/config.toml (or $CODEX_HOME)
palizade install-config --all --client codex --project   # this repo's .codex/config.toml
palizade install-hooks codex
```

Only the `[mcp_servers.<name>]` tables of wrapped servers are rewritten; the rest of the file, comments included, is left alone, and per tool settings such as `approval_mode` are kept. Variables the server needed (`env_vars`, `bearer_token_env_var`, `env_http_headers`) are forwarded to Palizade.

**Any other MCP client** that launches stdio servers: use `palizade wrap <server> -c /absolute/path/to/palizade.yaml` as the server command.

Finally, approve each server's current tool list and check coverage:

```bash
palizade lock approve <server>     # install-config prints these for you
palizade doctor --client <name>    # shows which servers and tools are protected
```

Placeholders in imported entries keep working: `${NAME}` and `${NAME:-default}` (Claude Code) and `${env:NAME}` (Cursor) are filled from your environment when Palizade starts the server or connects to its url. A header whose variable is unset is left out; a url whose variable is unset is an error. Remote servers with no static credentials are skipped, because they usually sign in with OAuth, which the stdio wrapper cannot do; run those through `palizade serve`, or pass `--include-remote` if they need no sign in. Servers using the legacy `sse` or `ws` transports are skipped with a message, since Palizade proxies stdio and Streamable HTTP only.

## Held Out Evaluation (AgentDojo)

[AgentDojo](https://github.com/ethz-spylab/agentdojo) v1.2.2 with the `important_instructions` attack, replaying each suite's scripted ground truth (an agent that does the user's task and then fully obeys the injection) through the default preset with every tool untrusted, and refusing every approval prompt:

| | Clean utility | Attack success |
|---|---:|---:|
| No defense | 97/97 (100%) | 593/949 (62.5%) |
| Palizade, first run (held out) | 67/97 (69.1%) | 42/949 (4.4%) |
| Palizade, after reviewing two suites | 68/97 (70.1%) | 11/949 (1.2%) |

This is a replay, not an LLM run, and the utility cost is real: tasks that send to an address read from untrusted content are blocked like attacks. Method, per suite numbers, approval modes and limits: [results/agentdojo](results/agentdojo/README.md). Reproduce with `pnpm eval:agentdojo`.

## How It Works

Palizade's core control is provenance, not content classification. Data returned by untrusted or source-classed tools is tagged as tainted. If that data later appears in a sink tool call, such as write, send, delete, shell, publish, or network egress, policy can block it, redact it, log it, or require user approval.

That means Palizade can block on provenance alone. A page or email does not need to contain obvious malicious text. If untrusted content flows into a privileged sink, the flow is visible to policy.

```text
MCP client
  |
  | JSON-RPC over stdio
  v
Palizade proxy
  | tools/list          hash + lock + scan metadata
  | tools/call request  classify tool + check taint into sinks
  | tools/call response scan + register provenance/taint
  | sampling/*          deny or approval-gate server model access
  v
Upstream MCP server
```

## Features

- Shared SQLite provenance for tool, resource, prompt and sensitive-origin content, with hidden-Unicode normalization, identifier/host skeletons and bounded decoded sink views.
- Sink checks for copied destinations, URL/host/email and tool-specific IDs, known-host lookalikes, sensitive egress and split outbound payloads.
- Persistent memory/vector provenance after approved writes, plus explicit pruning.
- Rule of Two, quarantine, rate and loop gates shared across wrapped processes; optional session destination grants.
- Critical filesystem targets, traversal/symlink checks and bounded escaped, masked approval diffs.
- Metadata locks, faithful lock diffs, dangerous-default detection and cross-server tool collision/shadowing checks.
- Dual-era stdio and Streamable HTTP, including a stdio bridge for remote servers and a protected local listener.
- Native client hooks and optional sandboxed stdio launch.
- Seven YAML presets, terminal/localhost approvals, payload-masked audit logs, optional counter metrics, hot reload, policy validation, status and draft learning commands.

Detection remains a signal: pattern-based secret/PII recognition and observable matching do not provide complete semantic DLP. See [known limits](#what-palizade-does-not-protect), [architecture](docs/architecture.md) and [detector coverage](docs/detector-coverage.md).

## What install-config Changes

Wrap one configured server:

```bash
palizade install-config filesystem
palizade lock approve filesystem
```

Or wrap every unprotected MCP server in the client config at once:

```bash
palizade install-config --all --dry-run
palizade install-config --all
```

`install-config --all` reads the MCP client's config, skips entries already routed through Palizade, rewrites the remaining entries in place, and adds each upstream server command to `palizade.yaml` with `trust: untrusted`. It prints the `palizade lock approve <server>` commands to run next instead of auto-starting arbitrary servers.

Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/path/to/workspace"]
    }
  }
}
```

After `palizade install-config filesystem`:

```json
{
  "mcpServers": {
    "palizade-filesystem": {
      "command": "/absolute/path/to/node",
      "args": [
        "/absolute/path/to/palizade/dist/index.cjs",
        "wrap",
        "filesystem",
        "-c",
        "/absolute/path/to/palizade.yaml"
      ]
    }
  }
}
```

Restart the MCP client after changing its config.

Verify with the real filesystem MCP server:

```bash
pnpm smoke:filesystem
```

That smoke uses the official `@modelcontextprotocol/server-filesystem` server and covers initialize, ping, client notifications, server `roots/list` requests, `tools/list`, a real `read_text_file` call, and a large payload.

## Regression Check (In Sample)

These are not benchmark results. Palizade's ASR harness translates a stratified sample of InjecAgent cases into MCP source-tool responses and sink-tool calls. The table below is generated by `pnpm eval:asr` and stored in [results/asr_table.md](results/asr_table.md).

| Category | N | ASR (off) | ASR (default) | ASR (strict) |
|---|---:|---:|---:|---:|
| Direct injection | 15 | 100% | 0% | 0% |
| Indirect/tool injection | 25 | 100% | 0% | 0% |
| Encoded/obfuscated | 10 | 100% | 0% | 0% |
| Total attacks | 50 | 100% | 0% | 0% |
| Benign FP rate | 25 | 0% | 0% | 0% |

Replay verification sample: 10; mismatches: 0.

Caption: Derived from [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), [Zhan et al., ACL 2024 Findings](https://arxiv.org/abs/2403.02691), pinned local snapshot `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, translated to MCP tool-call format with seed `424242`. This is not a run of the original benchmark. Of 225 total replay runs, 0 were classified as model refusals and 100 were Palizade blocks. **These figures are in-sample.** An earlier run let two attacks through (4% default, 2% strict). Inspecting them showed a bug in taint fingerprinting: fixed-stride substring windows only matched a verbatim copy when it sat at the same offset mod 24 in the source response and the sink argument. Fingerprints now use winnowing, which is position independent and is tested outside this corpus in `packages/taint/src/alignment.test.ts`. Because the fix came from looking at this corpus, a held-out set is needed before these numbers mean more than "no known misses". See [NOTES.md](NOTES.md) for methodology, inferred sink arguments, and benign fixture caveats.

## Demos

Run the local demos after `pnpm build`:

| Command | What it proves |
| --- | --- |
| `pnpm demo:cross-server` | Fetch-like source content taints one wrapped server, then a Gmail-style sink is blocked in another wrapped server. |
| `pnpm demo:benign-block` | Benign-looking source content with no injection text is blocked from entering `write_file` on provenance alone. |
| `pnpm demo:secret-block` | A detected fake AWS credential is registered as sensitive taint and blocked before message egress. |
| `pnpm demo:pii-redact` | PII in outbound email arguments is redacted and the sanitized call is forwarded. |
| `pnpm demo:egress-allowlist` | Tainted content is blocked to `evil.com` but allowed to a configured `good.com` destination. |
| `pnpm demo:email-block` | A mock `read_message` source taints email content and `send_email` is classified as a sink and blocked. |

Example audit shape:

```text
... block            request  claude_fetch_demo post_data rule=block-tainted-sink taint=...
  Tainted content is flowing into a sink tool.
```

Example client-facing block result:

```text
Palizade blocked this tool call. Rule: block-tainted-sink. Reason: Tainted content is flowing into a sink tool. Tool: send_email. This action was prevented by your local Palizade security policy.
```

## Debugging

`palizade taint prune` skips persistent memory provenance. `palizade taint prune --include-persistent` explicitly removes persistent records in the current profile as well as expired normal records. Approved tainted memory writes have no provenance TTL; later reads retain the original source in audit metadata.

Inspect quarantine with `palizade session quarantine`; clear it explicitly with `palizade session quarantine --clear [--session <id>]`. This clears quarantine only; seen-sensitive/untrusted flags and hard blocks remain active. High-score responses and blocked tainted/split/lookalike destinations quarantine the session; enforcing presets approval-gate subsequent sinks until expiry or operator clearance.

Exposure flags expire after `taint.exposure.ttlMs` (default 7200000, two hours), refreshed on each new untrusted or sensitive exposure. Native hooks isolate flags, quarantine, grants and counters by the client's `session_id` (Cursor's `conversation_id`), while profile-scoped taint records remain shared. `palizade session reset [--session <id>]` clears session flags, quarantine, grants and counters without deleting taint records. With `--session`, reset/quarantine target that native client session; without it, they target the configured wrapper profile/run scope.

Check local config and MCP coverage:

```bash
palizade doctor
palizade doctor --client-config "C:\Users\you\AppData\Roaming\Claude\claude_desktop_config.json"
```

`doctor` lists every configured MCP server and reports whether it is protected by Palizade or still a blind spot.

Inspect decisions:

```bash
palizade -c /absolute/path/to/palizade.yaml audit --last 15m
palizade -c /absolute/path/to/palizade.yaml audit --last 1h --action block
```

Operate a running setup:

- `palizade status [--json]` shows each server's transport, configured and last seen protocol era, lock state and sandbox; the policy file and hash; taint record counts (normal and persistent); quarantined sessions; sessions where the Rule of Two is armed (untrusted and sensitive content both seen); and the last 10 blocks.
- `palizade policy check [file]` validates a policy before you deploy it: schema and unknown keys (with a "did you mean" hint), rules that can never run because an earlier rule matches everything, conditions that can never be true (`labels_any: []`, `detector_score_gte` above `detector_score_lt`, an invalid `argument_regex`), and `server` or `tool` names that are not in `palizade.yaml` or `palizade.lock`. It exits 1 on errors, and on warnings too with `--strict`.
- `palizade learn --from-audit --since 7d` prints a draft YAML of tool classes and allowlist entries observed in audit. It never writes a file, and it does not suggest destinations that were only seen in blocked calls or with tainted data.
- Edits to `palizade.yaml`, the policy file and `palizade.allow.yaml` are picked up by running `wrap` and `serve` processes within about a second. An invalid edit is rejected: the previous version keeps running, the failure is audited and printed on stderr with the YAML path and a fix hint. Turn this off with `reload: { enabled: false }`; change the poll interval with `reload.intervalMs`.
- For SIEM ingestion, `metrics: { jsonl: .palizade/metrics.jsonl }` writes one line per decision with counters only (no payloads), rotating at `metrics.maxBytes` (default 64 MiB).

Common Windows and client gotchas:

- Desktop clients may spawn MCP servers without inheriting your shell `PATH`. `install-config` writes an absolute Node path and an absolute Palizade CLI path to avoid `.cmd` and `.ps1` shim issues.
- If Palizade is launched from a different working directory, pass `-c <absolute path to palizade.yaml>`.
- Claude Desktop stores MCP config in `claude_desktop_config.json`.
- Claude Code uses `.claude.json` / `claude mcp add`; its `claude mcp add` parsing can mis-handle `-c`, so use a `.cmd` wrapper that pins the config path, as shown in [examples/claude-code-fetch-demo.md](examples/claude-code-fetch-demo.md).
- Headless clients do not have an interactive terminal. Use `approvals.mode: localhost` and keep `http://127.0.0.1:32145/` open for interactive approval flows.
- If the model reports a tool failure that begins with `Palizade blocked this tool call`, the upstream tool is not broken. Palizade returned an MCP `isError` result because policy blocked the action.

If `doctor` says no config exists:

```text
No palizade.yaml found in current directory. Run 'palizade init' first, or pass -c <path>.
```

## What Palizade Does Not Protect

- Palizade only guards traffic through MCP servers it wraps, plus native tool hooks where `palizade install-hooks` is installed (Claude Code PreToolUse/PostToolUse, Cursor beforeShellExecution/beforeMCPExecution, Codex PreToolUse). Native tools without installed hooks remain unprotected, and shell parsing is heuristic — it extracts URLs, hosts, redirect targets, and suspicious constructs but is not a shell parser.
- It does not protect against a malicious MCP client or a compromised host OS.
- Pattern-based secret and PII detection misses obfuscated, split, transformed, or custom secrets. See [docs/detector-coverage.md](docs/detector-coverage.md).
- Taint matching uses observable fragments/tokens, lightweight SimHash and temporal evidence. Rule of Two gates paraphrased remote/memory actions after both exposure flags are set; it does not provide unrestricted semantic matching.
- Outbound windows are process-local. Splits across wrapper/hook processes or independently padded encoded shards can evade concatenation; the later adaptive evaluation must measure these cases.
- Critical paths are checked against the local filesystem at decision time. They do not enforce a malicious server's actual I/O or prevent subsequent symlink races. Unknown edit formats cannot produce a complete approval diff.
- Client-rendered side effects such as automatically fetched Markdown images are outside observable proxy/hook traffic.
- Input-required gating currently covers tool results; prompt/resource input-required handlers, full discover schemas, structured string constraints and listener inbound parameter-header disagreement remain limited. The [integration report](docs/v0.4-report.md) distinguishes these gaps from tested behavior.
- Substring fingerprints cover all of a tool response up to about 17 KB; for longer responses they cover the first and last 8 KB or so. Text copied from the middle of a long response is caught only by token, fuzzy, or temporal matching. Urls, email addresses and other tokens are extracted from the whole response.
- The in sample benign corpus is small and synthetic: 17 of its 25 fixtures contain no sink call and cannot produce a false positive. The AgentDojo replay is the better utility measure, and shows the real cost: a task that sends to an address it read from untrusted content is blocked like an attack.
- Streamable HTTP is supported for both protocol eras, but request-scoped SSE notifications from a 2026-07-28 upstream are relayed to the client only when the client asks for `text/event-stream`; a JSON-only client receives the final response and audit still records every upstream notification.
- The transparent listener shares one upstream session per configured server: several legacy-era clients cannot each hold their own `Mcp-Session-Id` through a single listener. Use `palizade wrap` (one bridge process per client) when that matters.
- Tool name collision and shadowing checks only compare servers wrapped by Palizade that share one state directory, and only from the moment each server has answered `tools/list`. The server that lists a shared name first keeps it until that server restarts; after that both copies are withheld until one is renamed or removed from `palizade.yaml`.
- Sandboxing is opt-in and limited by its backend. A network `allowlist` is only enforced with seatbelt, or with docker plus a `sandbox.dockerNetwork` internal network; other combinations are refused unless you set `advisoryNetwork: true`, in which case the server could ignore the proxy; seatbelt restricts writes and network but not reads; Palizade does not sandbox `url` servers or the client itself, and it does not harden the docker daemon or the image you choose.
- Hot reload only applies settings the interception engine reads per message (policy, egress allowlist and mode, limits, trust, tool classes and other per-server classification). Changes to stores, sinks, detectors, transport or the upstream launch are reported and need a restart. A message already being processed when a reload lands may evaluate its later rules against the new policy. `palizade learn` output is a starting point built from what was observed, not a reviewed policy.

These are scope boundaries, not footnotes. Palizade is strongest when sensitive capabilities are exposed through wrapped MCP servers and policy is reviewed for each server.

## Threat Model

In scope:

- Tool poisoning through malicious or compromised `tools/list` descriptions.
- Indirect prompt injection through tool responses such as pages, issues, PR comments, emails, files, and docs.
- Rug pulls where tool descriptions or schemas change after approval.
- Exfiltration or side effects caused by tainted content flowing into sink tools.
- MCP privilege escalation through server-initiated model access.

Out of scope:

- Native client tools without installed hooks.
- Host compromise.
- Malicious clients that bypass or tamper with the proxy.
- Complete semantic DLP, arbitrary memory rewriting, or unobserved side effects.

For depth, read [docs/architecture.md](docs/architecture.md), [docs/policy.md](docs/policy.md), and [docs/detector-coverage.md](docs/detector-coverage.md).

## Policy

Policies are YAML documents with first-match-wins semantics:

```yaml
version: 1
defaults:
  action: allow
  on_error: block

rules:
  - id: block-tainted-sink
    when:
      direction: request
      method: tools/call
      tool_class: sink
      taint: true
    action: block
    reason: Tainted content is flowing into a sink tool.
```

Preset guidance:

| Preset | Use it when |
| --- | --- |
| `policies/audit-only.yaml` | You want to observe what Palizade would flag without enforcement. |
| `policies/interactive.yaml` | A human should be able to approve legitimate tainted sink calls. |
| `policies/default.yaml` | Hard-block general copied-content sinks, with explicit memory approval and session gates. |
| `policies/strict.yaml` | You want stricter metadata, output, unknown-tool, taint, and egress enforcement. |
| `policies/egress.yaml` | You want the default posture plus opt-in secret/PII outbound controls. |
| `policies/coding-agent.yaml` | Add shell and tainted critical-write protection to default. |
| `policies/research-readonly.yaml` | Confine side effects to one configured output directory. |

Full reference: [docs/policy.md](docs/policy.md).

v0.4 behavior changes:

- Enforcing presets block destinations copied from untrusted content and known-host lookalikes, including tool-specific channel/account/repository IDs. Unicode and decoding checks use separate matching views.
- Default gates split matches; strict and egress block them. Default, strict and interactive gate remote/memory sinks after both untrusted and sensitive exposure, even for paraphrases. Quarantine, rate and loop gates count denied attempts; explicit session grants never bypass hard blocks.
- Critical writes require approval after hard blocks; strict and coding block tainted critical writes, and research blocks all critical writes. Whole package.json writes are protected. Semi/untrusted annotations can raise risk but cannot make a risky tool read-only; trusted annotations and administrator overrides retain priority.
- Tainted memory writes require approval in default, interactive and egress; strict blocks them. Approved observable provenance persists beyond TTL. Default's generic copied-content sink block remains, with this explicit memory exception.
- Metadata collisions/shadowing are blocked and hidden Unicode is sanitized; audit-only logs those findings. Common built-in names are labelled without being blocked. Lock approval stores snapshots, prints escaped diffs and asks in a TTY (`--yes` skips the prompt).
- All enforcing presets approval-gate elicitation. Strict now blocks strong suspicious output before sanitization. Destination/query, secret and split hard blocks precede generic approval/redaction rules. Egress exceptions cannot bypass critical, temporal, quarantine, rate or loop gates.
- `egress.mode` remains `open` by default. Use `approve_new` with default for allow once/always/deny; remembered grants go to the separate `palizade.allow.yaml`. Strict blocks new destinations even with open mode. Typed IDs use `egress.allowlist.destinations`, for example `channel_id:C123`.
- Running wrap/serve processes reload valid policy/config/allowlist edits by default. Invalid edits keep the last valid version and are audited; `reload.enabled: false` restores fail-closed learned-file errors. Startup still rejects invalid files. Schema validation rejects unknown keys with path/line hints.
- Optional raw audit capture masks observable tainted payloads entirely and masks known sensitive text otherwise. Copied destinations are masked in audit and approvals. Sandboxing remains opt-in, metrics remain off, and existing stdio configs keep working.

## Commands

Select a starter with `palizade init --preset coding-agent` or `palizade init --preset research-readonly --output-dir ./output`. Initialization copies the current embedded preset and preserves existing files unless `--force` is supplied. Ordinary `init` selects default; strict initialization also sets allowlist-only egress.

```bash
palizade init [--preset <name>] [--output-dir <path>]
palizade install-config <serverName>
palizade install-config --all
palizade wrap <serverName>
palizade serve
palizade status [--json]
palizade hook <client> [event]
palizade install-hooks <client>
palizade policy check [file] [--json] [--strict]
palizade policy test <files...> [--policy <file>]
palizade learn --from-audit --since 7d [--server <name>]
palizade lock approve <serverName>
palizade lock diff <serverName>
palizade detectors install promptguard2
palizade detectors verify heuristic
palizade scan [--json] [--fail-on high|medium|low]
palizade why [--last 24h] [--limit 5]
palizade tools [serverName] [--catalog]
palizade allow host|email <value...>
palizade allow list
palizade allow remove host:<host> | email:<address>
palizade audit --last 1h
palizade audit verify
palizade audit prune --older-than 30d
palizade taint prune [--include-persistent]
palizade session quarantine --clear [--session <id>]
palizade session reset [--session <id>]
palizade doctor
```

### Checking a machine

`palizade scan` reads every MCP client config it knows (Claude Desktop, Claude Code user, local and project scope, Cursor user and project) plus `palizade.yaml`, and reports servers that are not routed through Palizade, credentials written in plain text, packages and images run without a fixed version, plain http urls, legacy transports, and locked tool descriptions with hidden text, cross server references or instruction like wording. It starts no servers. `--json` and `--fail-on medium` make it usable in CI. To check a repository's committed MCP configs (`.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml`) for leaked credentials and unpinned packages on every push:

```yaml
- run: npx -y palizade@0.4.0 scan --project-only --skip unprotected --fail-on low
```

### When something is blocked

`palizade why` explains the last few blocks and approval prompts in plain language: which rule fired, where the tainted data came from, the destination, and what you can do (classify a tool, allow a host, approve, or reset the session). `palizade allow host api.example.com` or `palizade allow email *@example.com` adds destinations to `palizade.allow.yaml`; `palizade allow list` shows them next to the ones in `palizade.yaml`. Allowing a destination never overrides a block on a destination that was copied from untrusted content.

### Tool classification

Common servers (filesystem, fetch, memory, git, GitHub, Slack, Puppeteer, Playwright, Brave Search, time, sequential thinking) are classified from a built in catalog, so their tools work under `trust: untrusted` without hand written `toolClasses`. `palizade tools` prints each locked tool's class and why; `palizade tools --catalog` lists the catalog. See [how tools are classified](docs/policy.md#how-tools-are-classified).

### Native client tool hooks

`palizade install-hooks <client>` writes hook entries for `claude-code` (`~/.claude/settings.json`), `cursor` (`~/.cursor/hooks.json`, `failClosed: true`), or `codex` (`~/.codex/hooks.json`) — backing up and merging without ever overwriting malformed JSON. The `palizade hook` command reads the client's hook JSON on stdin and prints the client's decision format (Claude Code/Codex `hookSpecificOutput.permissionDecision`, Cursor `permission`).

Hooks reuse the same SQLite taint store, policy, and audit as the proxy: Bash/Shell/apply_patch commands run the full sink check (shell-command role, network destinations, critical-path redirects), Write/Edit are gated on critical paths and tainted content, WebFetch URLs run destination checks, and PostToolUse of Read/WebFetch/Grep/Glob registers taint that later commands are matched against. Hooks fail closed by default (`hooks.failMode: closed`): a crash or timeout exits 2 (block), never allow. Claude Code tool hooks are also installed with `onFailure: block`, so a missing or crashing hook command denies the call instead of letting it through (Claude Code 2.1.295 or newer).

### Destinations you type

Provenance alone cannot tell "email the invoice to billing@vendor.example", typed by you, from the same address planted in a page the agent read. The prompt hooks close that gap: `install-hooks` also registers `UserPromptSubmit` (Claude Code, Codex) and `beforeSubmitPrompt` (Cursor), and Palizade remembers the destinations in your prompt: email addresses, exact urls, hosts, @handles and #channels, account and IBAN style numbers, and phone numbers. A later call to one of those is not treated as copied from untrusted content; everything else in the call is still checked, and a destination that only appeared in a page is still blocked. Only keyed hashes are stored, never the values. Prompt hooks never block your message, even if Palizade fails. Turn it off with `taint.userIntent.enabled: false`.

### Remote (HTTP) MCP servers

Palizade proxies remote MCP servers declared with `url` instead of `command` in `palizade.yaml`:

```yaml
servers:
  remote:
    url: https://example.com/mcp
    headers:
      Authorization: "${GITHUB_TOKEN}"
```

`palizade wrap <server>` bridges the remote server over stdio so existing client integrations keep working. `palizade serve` runs a transparent local listener at `http://127.0.0.1:32146/mcp/<serverName>`: the upstream is always taken from config (never from request input), client `Authorization` headers are forwarded only to the configured upstream origin (never to redirect targets), `401`/`403`/`WWW-Authenticate` pass through untouched for OAuth discovery, and the listener requires Palizade's own bearer token (generated at `init`, stored at `.palizade/listener.token`, sent as `X-Palizade-Token`). Both protocol eras are supported: 2025-11-25 (initialize, sessions, GET SSE streams) and 2026-07-28 (POST only, `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Param-*` headers, request-scoped SSE).

RFC 8707 caveat: forwarded tokens must target the configured upstream resource. Palizade does not mint upstream tokens or act as an OAuth authorization server. The listener has not been validated as an OAuth-terminating gateway; avoiding TLS termination alone does not establish audience compliance. MCP forbids accepting another resource's token and passing it downstream. See the official [authorization requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and [token-passthrough guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough).

### Sandboxed stdio servers

Stdio servers can optionally be launched inside a sandbox. The default is `none` (unchanged behavior):

```yaml
servers:
  filesystem:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
    sandbox:
      type: docker            # none | docker | bubblewrap (Linux) | seatbelt (macOS); Windows: docker only
      image: node:22-slim
      writable: ["out"]       # cwd is mounted read-only; only these paths are writable
      network: allowlist      # none (default) | allowlist
      allowHosts: ["registry.npmjs.org"]
      passEnv: ["LANG"]       # no host environment is passed except these names and `env`
```

The shorthand `sandbox: docker` uses those defaults with `network: none`. Every spawn is written to audit with secrets masked, and `palizade doctor` lists servers that run unsandboxed.

Development and eval commands:

```bash
pnpm install
pnpm build
pnpm test
pnpm eval
pnpm eval:asr
pnpm eval:detectors
pnpm bench:latency
pnpm smoke:filesystem
```

Optional PromptGuard2 setup is explicit. Palizade does not download model artifacts during `init`.

```bash
palizade detectors install promptguard2
palizade -c palizade.promptguard2.yaml detectors verify promptguard2
pnpm eval:combined
```

## Status And Clients

- `install-config` supports Claude Desktop, Claude Code (user, local and project scope), Cursor (user and project) and Codex (user and project); other clients take a manual `palizade wrap` entry.
- Remote servers that sign in with OAuth cannot go through the stdio wrapper; use `palizade serve` for them.
- Coverage includes wrapped MCP traffic and installed native-hook events; live client hook activation needs verification.
- Claude Desktop live validation has exercised tainted write blocking.
- Claude Code support is documented with a non-native fetch/post MCP demo in [examples/claude-code-fetch-demo.md](examples/claude-code-fetch-demo.md).
- Real filesystem server smoke test is available through `pnpm smoke:filesystem`.
- Overhead from `pnpm bench:latency` (Linux container, Node 22, single run): pass-through call p50 0.3 ms in process; on the default SQLite taint store with 200 stored 4 KB pages, fingerprinting a page takes p50 about 2.5 ms and checking a sink call takes p50 about 2.5 ms. A 1 MB tool result costs about 0.5 s and a 5 MB result about 3 s. Excludes the stdio hop to the upstream server.

## Security And Privacy

- Audit logs hash payloads by default.
- Raw capture requires `audit.captureRawPayloads: true`; observable tainted payloads are replaced by a redaction marker and other text receives known-secret/PII masking.
- SQLite taint fingerprints are HMAC-protected by `.palizade/taint.key`; the key is local and never printed.
- Policy evaluation errors fail closed in enforcing presets.
- Localhost approval is tokenized, one-time, POST-only, loopback-bound, and served from a persistent inbox at `http://127.0.0.1:32145/` by default.
- Unknown tools on untrusted servers are blocked by the default policy; unknown tools on semi-trusted servers require approval; unknown tools on trusted servers are audit-logged.

## Package Layout

```text
packages/core       MCP transport, sessions, interception, lockfile, classification
packages/taint      provenance records, fingerprints, matching, temporal taint
packages/policy     YAML policy parser and evaluator
packages/detectors  heuristic, PromptGuard2, secret, and PII detectors
packages/audit      JSONL and SQLite audit sinks
packages/approvals  terminal, localhost, and test approval providers
packages/cli        init, wrap, lock, audit, detector, install, and doctor commands
eval/               InjecAgent-derived MCP ASR and local replay harnesses
examples/           reproducible demos and real-server smoke tests
policies/           shipped policy presets
docs/               architecture, policy, validation, and coverage notes
```

## Standards Mapping

| Risk area | Palizade control |
| --- | --- |
| OWASP LLM01 Prompt Injection | Tool metadata scanning, response scanning, spotlighting, taint registration, sink gating |
| OWASP LLM06 Sensitive Information Disclosure | Sensitive taint tracking, secret/PII detection, redaction, egress allowlists, masked audit logs |
| OWASP LLM07 Insecure Plugin Design | Tool lockfile, tool class policy, unknown-tool handling, server-initiated sampling controls |
