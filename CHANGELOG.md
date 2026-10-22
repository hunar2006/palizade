# Changelog

All notable changes to the `palizade` npm package. Dates are release dates.

## 0.4.0 (2026-10-21)

The largest release so far: native tool hooks, remote MCP servers, the 2026-07-28 MCP protocol, session level gates, and a hardened matcher. Requires Node.js 22.13 or newer.

### Upgrading: behavior changes

Read these before upgrading an existing setup. Most of them make Palizade block or ask more often.

- **Stricter config validation.** Unknown keys in `palizade.yaml` and policy files are now errors, reported with the YAML path, line number and a fix hint.
- **New rules in the shipped presets.** `default`, `interactive`, `strict` and `egress` now block destinations that were copied from untrusted content and lookalike hosts, ask before outbound actions once a session has seen both untrusted and sensitive data (Rule of Two), ask before writes to critical files (agent and IDE configs, CI workflows, git hooks, `package.json`, `.env*`, shell rc files), and gate quarantined, rate limited and looping sessions. Regenerate your policy with `palizade init --force`, or merge the new rules by hand.
- **More tools count as remote writes.** Names with add, invite, update, set, assign, grant, share, rename, archive, reply, forward, schedule or cancel are now sinks, so they get taint and destination checks instead of the unknown tool rules.
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
- **Held out evaluation on AgentDojo:** `pnpm eval:agentdojo` replays AgentDojo ground truth traces through Palizade and scores them with AgentDojo's own checks. Results and method are in `results/agentdojo`.
- **Ask before deletes after untrusted content:** new `session_untrusted` policy field and `approve-delete-after-untrusted` rule in the default, interactive and strict presets.
- **Destinations you type:** prompt hooks (`UserPromptSubmit` for Claude Code and Codex, `beforeSubmitPrompt` for Cursor) record the destinations in your prompt, as keyed hashes, and calls to them are no longer blocked as copied from untrusted content. New `user_stated_destination` policy field and `taint.userIntent` settings. Prompt hooks never block a prompt.
- **Safer hook installs:** Claude Code tool hooks get `onFailure: block`. Re-running `install-hooks` updates Palizade's entries in place instead of adding duplicates (Cursor entries were duplicated before).
- **`palizade setup <client>`:** one command that creates `palizade.yaml` if needed, wraps the client's MCP servers, installs native tool and prompt hooks, and with `--lock` approves each new server's tools.
- **Following links:** opening a url exactly as an untrusted page or search result wrote it is allowed in the default, interactive and coding agent presets (`copied_link_only`, `allow-following-copied-link`), so research agents can follow links. Urls with anything added, sends, writes and sessions under Rule of Two are still checked as before.
- **Account takeover guard:** changing a password, key or token after untrusted content asks first (`approve-credential-change-after-untrusted`).
- **Catalog:** 17 more servers (Notion, Sentry, HubSpot, Heroku, MongoDB, Postgres, GitLab, Google Maps, Exa, Tavily, Firecrawl, Context7, Apify, Chrome DevTools, Browserbase, Figma, Desktop Commander), written from their real tool lists and tested against them.
- **Usability:** loop and destination limits use a 10 minute window (`limits.windowMs`) and only count outbound calls, so long coding sessions are not asked to approve every command. `lock approve` waits 60 seconds by default, since a first `npx` run downloads the server. The CLI starts faster (Node compile cache) and no longer prints the `node:sqlite` experimental warning.
- **Tool metadata is judged per tool.** A suspicious description now withholds that one tool instead of the whole server, and instruction style wording that every real tool description uses ("use this tool when", "call X first") counts for little on descriptions. Emoji variation selectors are no longer reported as hidden text. Before this, the default policy withheld every tool of Apify, Firecrawl, HubSpot and MongoDB; across 26 published servers (318 tools) none is withheld now (`results/real-servers*.md`), while a poisoned description in the same list is still withheld.
- **`palizade policy upgrade`:** adds the shipped preset's new rules to your policy file at the right position, keeping your own rules and comments. `palizade doctor` reports missing preset rules and missing or outdated hook entries.
- **MCP servers that are not wrapped, through hooks:** Claude Code hooks now also match `mcp__*` tools. Calls to servers Palizade does not wrap, such as remote servers that sign in with OAuth, are checked as untrusted servers (`hooks.mcpTrust`) against the shared taint store; servers that are wrapped are left to their proxy.
- **Docs:** `SECURITY.md` (private reporting and scope) and `CONTRIBUTING.md` (setup, evaluation rules, how to add catalog entries and policy tests).
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
- Object keys are scanned: data placed in an argument key (`{"<copied text>": true}`) is checked for taint, secrets and personal data, and data bearing keys in untrusted results are recorded so copies are traced. Short identifier keys such as `id` are treated as structure.
- Substring fingerprints of long tool results now cover the end as well as the start, within the same storage budget, since injected text is often placed at the bottom of a page.
- The SSE parser now bounds a partial line and an unterminated event, so a remote server cannot exhaust memory by streaming one endless line or data without a blank line.

### Compatibility fixes

- **Remote servers built with the official SDKs work over the HTTP bridge.** In the 2025-11-25 era, a server may answer a POST with an SSE stream, which the TypeScript and Python SDKs do by default. Palizade only read JSON bodies, so it dropped the replies.
- **`lock approve` and `lock diff` work with Python stdio servers.** They now send `initialize` and `notifications/initialized` before `tools/list`, which servers built on the Python SDK require. Tool listing also follows `nextCursor`, so paginated tool lists are locked completely, and a server that exits early gives a clear error.
- **The HTTP lock probe no longer records an empty tool list** when a legacy server answers the first probe with an error; it falls back to the handshake.
- **Catalog tools are raised to sink only by `destructiveHint`, not `openWorldHint`.** Playwright marks every tool open world, which turned read only tools like `browser_snapshot` into sinks. The Playwright entry also covers its newer tools.

### Performance

- Stdio framing copies a large message once instead of once per chunk: a 20 MB tool result in 64 KB chunks now takes about 60 ms instead of about 800 ms.
- Large tool results are fingerprinted once instead of twice, and SimHash no longer uses BigInt (same output, so stored fingerprints still match): a 5 MB result goes from about 10 s to about 3 s of Palizade time.

### Known limits

- The published InjecAgent results are an in-sample regression check, not a benchmark result. See `docs/evaluation-plan.md`.
- Shell command analysis in hooks is heuristic.
- Hooks have unit tests but have not yet been validated inside live Claude Code, Cursor and Codex sessions.
- Client rendered exfiltration (for example Markdown images) is not visible to Palizade.

## Earlier releases

0.3.0 and 0.3.1 are tagged in this repository. 0.3.2 was published to npm on 2026-07-09. See the git history for details.
