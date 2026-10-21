# Palizade

A local firewall for AI agents. Palizade tracks where data came from (taint tracking) and stops untrusted content, such as a hidden instruction in a web page, from driving risky actions like sending email, writing files, or running shell commands.

Requires Node.js 22.13 or newer. Works on Windows, macOS and Linux.

```bash
npx palizade init
npx palizade install-config --all      # wrap the MCP servers in your client config
npx palizade install-hooks claude-code # also cover native tools (also: cursor, codex)
npx palizade doctor                    # show what is and is not protected
```

What it covers:

- MCP servers over stdio and Streamable HTTP (both the 2025-11-25 and 2026-07-28 protocol versions).
- Native Bash, Read, Write and WebFetch tools in Claude Code, Cursor and Codex through hooks.
- Destinations copied from untrusted content, encoded or split exfiltration, writes to agent configs and CI files, memory poisoning, and tool description tampering.

What it does not cover: a compromised machine or client, native tools without hooks installed, and links or images rendered by the client itself.

Full documentation, threat model and source: https://github.com/hunar2006/palizade
