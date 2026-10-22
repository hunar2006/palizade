# Changelog

All notable changes to the `palizade` npm package. Dates are release dates.

## 0.4.0 (2026-10-21)

The largest release so far: native tool hooks, remote MCP servers, the 2026-07-28 MCP protocol, session level gates, and a hardened matcher. Requires Node.js 22.13 or newer.

### Upgrading: behavior changes

Read these before upgrading an existing setup. Most of them make Palizade block or ask more often.

- **Stricter config validation.** Unknown keys in `palizade.yaml` and policy files are now errors, reported with the YAML path, line number and a fix hint.
- **New rules in the shipped presets.** `default`, `interactive`, `strict` and `egress` now block destinations that were copied from untrusted content and lookalike hosts, ask before outbound actions once a session has seen both untrusted and sensitive data (Rule of Two), ask before writes to critical files (agent and IDE configs, CI workflows, git hooks, `package.json`, `.env*`, shell rc files), and gate quarantined, rate limited and looping sessions. Regenerate your policy with `palizade init --force`, or merge the new rules by hand.
- **Descriptions from untrusted servers can only raise risk.** On `semi` and `untrusted` servers, a tool description or title can add sink capabilities but no longer turns an unknown tool into a source. Such tools now hit the unknown tool rules (block on untrusted, approval on semi) unless the catalog or `toolClasses` names them.
- **Annotations from untrusted servers can only raise risk.** On `semi` and `untrusted` servers, `readOnlyHint` no longer turns a risky or unknown tool into a source.
- **Hooks fail closed.** Any hook error (bad config, oversized or invalid input, timeout) denies the tool call with exit code 2 unless `hooks.failMode: open`.
- **Sandbox network allowlists must be enforceable.** `network: allowlist` with docker and no `dockerNetwork`, or with bubblewrap, is rejected at startup unless you set `advisoryNetwork: true`, because the server could ignore the proxy.
- **Library users:** `InterceptionEngine` now validates its config on construction and rejects invalid values that were previously ignored.
- **Packaging:** the npm package now ships a single self contained bundle (`dist/index.cjs`) and no type declarations.

### Added

- **Native tool hooks** for Claude Code, Cursor and Codex: `palizade hook` and `palizade install-hooks <client>`. Native Bash, Read, Write and WebFetch share the same taint store, policy and audit log as MCP traffic.
- **Remote MCP servers** over Streamable HTTP, for both the 2025-11-25 and 2026-07-28 protocol eras: a stdio bridge (`wrap` a server that has a `url`) and a local listener (`palizade serve`) with its own bearer token, Origin checks, loopback binding, and Authorization forwarded only to the configured upstream.
- **MCP 2026-07-28 support:** `input_required` results (sampling denied, elicitation gated, sensitive form fields refused, URL mode treated as egress), `server/discover` locking, re-locking on `tools/list_changed`, and taint on `structuredContent`.
- **Matcher hardening:** decoding of base64, base64url, hex, percent, HTML entity and escape encodings before matching; split secret correlation across calls to the same destination; lookalike host detection; per tool argument roles for ID style destinations.
- **Session gates:** Rule of Two, quarantine, rate limits and loop detection, with `palizade session` commands to inspect and reset them.
- **Protected targets and memory:** approval with a diff for critical file writes; memory writes treated as sinks with persistent provenance.
- **Tool metadata hardening:** hidden Unicode in descriptions and schemas, dangerous defaults, cross server shadowing and name collisions, and `palizade lock diff` with escaped characters.
- **Egress modes:** `open`, `approve_new` and `allowlist_only`, with "allow always" grants stored in `palizade.allow.yaml`.
- **Optional sandboxed launch** for stdio servers: docker (including Windows), bubblewrap and seatbelt.
- **Operations:** hot reload, `palizade policy check`, `palizade status`, `palizade learn --from-audit`, optional metrics JSONL, and `doctor` coverage reports.
- **Presets:** `coding-agent` and `research-readonly`.
- **`palizade policy test`:** YAML test cases for policies, with strict field checking; the default and strict presets ship with their own cases.
- **`palizade scan`:** one command that checks all MCP client configs and `palizade.yaml` for unprotected servers, plaintext secrets, unpinned packages and images, plain http urls and suspicious locked tool metadata, without starting servers.
- **`palizade why` and `palizade allow`:** plain language explanations of recent blocks and prompts with suggested fixes, and commands to add, list and remove allowed hosts and email addresses.
- **Tool catalog and schema signals:** built in classes for common MCP servers, chosen by the package, image or url in your config; input schema property names raise risk; `palizade tools` shows each tool's class and the reasons; audit events record `classificationReasons`.
- **Client setup:** `install-config` now supports Claude Code and Cursor (user configs, project configs with `--project`, Claude Code local scope with `--local`, and Codex `config.toml` with only the changed tables rewritten), carries over remote server headers, and expands `${NAME}`, `${NAME:-default}` and Cursor `${env:NAME}` placeholders when servers start. Legacy `sse` and `ws` servers are skipped with a reason. Remote servers with no static credentials are skipped unless `--include-remote` is given, since wrapping would break an OAuth sign in.
- **CI** on Windows, macOS and Linux with Node 22 and 24, and a tag-only release workflow with npm provenance.

### Security fixes since the v0.4 integration

- Hooks no longer fail open on oversized input, invalid JSON or a broken config.
- Rule of Two exposure flags now expire (2 hours by default), and native hook sessions are isolated per client session.
- Every Unicode default ignorable code point is treated as hidden, not just a hand picked list.
- Hosts and email addresses are compared in one canonical form for allowlist and provenance checks.

### Known limits

- The published InjecAgent results are an in-sample regression check, not a benchmark result. See `docs/evaluation-plan.md`.
- Shell command analysis in hooks is heuristic.
- Hooks have unit tests but have not yet been validated inside live Claude Code, Cursor and Codex sessions.
- Client rendered exfiltration (for example Markdown images) is not visible to Palizade.

## Earlier releases

0.3.0 and 0.3.1 are tagged in this repository. 0.3.2 was published to npm on 2026-07-09. See the git history for details.
