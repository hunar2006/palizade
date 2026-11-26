# Release verification

Run the test matrix and install the packed tarball for the release candidate. Run the following checks in **Claude Desktop, Claude Code, Cursor, Codex, and Gemini CLI** using disposable workspaces, a harmless local MCP server, and a real model. Claude Desktop should exercise its wrapped MCP server. Check the native tool path for the other four clients and confirm the audit records and `palizade doctor` agree with the observed coverage.

1. Run a user-requested read and a harmless tool call permitted by the policy. Count planned clean tasks, completed tasks, policy blocks on clean tasks, and approval prompts. Check the actual result of each task.
2. Add an explicit test policy rule denying an inert marker, such as `PALIZADE_SMOKE_DENY`, and ask the client to make the corresponding tool call. Count a denial only when the Palizade audit shows the test rule and the tool did not execute.
3. For any unknown tool stopping legitimate work, use `palizade learn --session <id>` to rank the affected tools. Compare `palizade tools <server>` with the server documentation and confirm `toolClasses` and `argumentRoles` before applying them. Rerun the same clean tasks, record the counts before and after, and keep the explicit denial check in both runs.

Keep the client/model versions, operating system, commands, policy, and counts in the release notes or a reviewable test record. Exclude prompts, audit payloads, and credentials. The payload test suite and runs with a scripted provider are useful for checking the integration, and live evidence requires a real model workflow.

## Windows integration evidence from November 18, 2026

These checks used the installed clients with local scripted responses and a temporary policy that denies an inert marker. Each client completed the permitted action and produced an audited denial for the second action.

| Client | Version | Path | Clean completed | Confirmed denials |
| --- | --- | --- | ---: | ---: |
| Claude Code | `2.1.327` | Native Bash | 1/1 | 1/1 |
| Codex CLI | `0.170.0` | Native hook on a local MCP tool | 1/1 | 1/1 |
| Gemini CLI | `0.63.0` | Native shell command | 1/1 | 1/1 |

The real-model Codex attempt reached the provider's quota limit. The live-model release gate still requires real-model results.

## Publish a verified candidate

Tag the tested commit on `main`. Then dispatch **Release** against that tag and supply the verification JSON. A tag push alone leaves the package unpublished. The workflow checks that the JSON matches the tag's commit and version, that all five clients completed their clean tasks without false blocks, and that every planned denial was confirmed. It reruns the release tests before publishing with the configured npm credential.

```sh
node -e 'process.stdout.write(JSON.stringify({client_verification:require("node:fs").readFileSync(process.argv[1],"utf8")}))' evidence.json |
  gh workflow run release.yml --ref v0.4.0 --json
```

The JSON has `commit` (full SHA), `version`, and a `clients` object with the keys `claude-desktop`, `claude-code`, `cursor`, `codex`, and `gemini`. Each entry must include these fields with actual results.

| Field | Value |
| --- | --- |
| `mode` | `live` |
| `clientVersion`, `platform`, `model` | Nonempty strings identifying the run |
| `cleanTasks`, `completedTasks` | Positive integers. The counts must agree. |
| `falseBlocks`, `approvals` | Nonnegative integers. `falseBlocks` must be zero for this smoke check. |
| `deniedTests`, `confirmedDenials` | Positive integers. The counts must agree. |

The workflow validates the submitted record. The release operator is responsible for recording and reviewing actual runs.
