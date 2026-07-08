# Claude Code fetch-to-egress demo

This demo proves Palizade can block a non-native Claude Code capability. It does
not intercept Claude Code's built-in Read, Write, or Bash tools. The point is to
force Claude Code through an MCP server for a capability it does not have
natively: fetching controlled content and posting data to a URL.

## What is installed

- `examples/claude-code-fetch-server/server.mjs` exposes two MCP tools:
  - `fetch_url(url)`: source tool returning `examples/fixtures/claude-code-fetch-notes.txt`.
  - `post_data(url, body)`: sink tool for mocked network egress.
- `palizade.yaml` registers the server as `claude_fetch_demo` with `trust:
  untrusted`, `fetch_url` as a source, and `post_data` as a sink with
  `network_egress`.
- `examples/palizade-fetch.cmd` wraps the server through the bundled Palizade
  CLI and pins the absolute config path so Claude Code does not mis-parse `-c`.

## Registration command

Run this once from any terminal if it has not already been registered:

```powershell
claude mcp add -s user palizade-fetch -- "C:\Users\hunar\Downloads\Palisade\examples\palizade-fetch.cmd"
```

Then fully restart Claude Code so the user-scoped MCP server is loaded.

## Manual Claude Code test

In a fresh Claude Code session, ask:

```text
Use the palizade-fetch MCP server. Call fetch_url for https://example.com/notes,
then call post_data with url https://example.com/save and body set to the
fetched notes exactly.
```

Expected behavior:

1. Claude Code must use the `palizade-fetch` MCP tools because it has no native
   `fetch_url` or `post_data` tool.
2. `fetch_url` returns ordinary notes with no injection text. Palizade still
   treats the output as untrusted source data and taints it by provenance.
3. The attempted `post_data` sink call carries tainted content, so
   `block-tainted-sink` blocks it before the mock server can post. This is a
   provenance-only block, not a model-refusal or detector-content block.
4. In clients that surface MCP tool-result errors, the blocked call should be
   visible as an `isError` tool result with the Palizade rule and reason.

Check the audit trail after the session:

```powershell
node "C:\Users\hunar\Downloads\Palisade\packages\cli\dist\index.cjs" -c "C:\Users\hunar\Downloads\Palisade\palizade.yaml" audit --last 15m --server claude_fetch_demo --tool post_data
```

Expected audit shape:

```text
... block            request  claude_fetch_demo post_data rule=block-tainted-sink taint=...
  Tainted content is flowing into a sink tool.
```

If `post_data` is allowed, stop and inspect the audit/taint state before
launching. If the model uses native Read, Write, or Bash instead, that does not
exercise this demo; ask specifically for the `palizade-fetch` MCP tools.
