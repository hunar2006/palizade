# Contributing

## Setup

Requires Node.js 22.13 or newer and pnpm.

```bash
pnpm install
pnpm build
pnpm test            # unit and integration tests
pnpm eval            # protocol regression suite
pnpm eval:asr        # in sample InjecAgent regression check
pnpm smoke:filesystem
pnpm bench:latency
pnpm eval:real        # lists tools from 8 reference servers (needs npx and uvx)
pnpm eval:real:more   # 18 more servers; credentials are placeholders
```

The held out AgentDojo evaluation needs Python with `pip install agentdojo==0.1.35`:

```bash
PALIZADE_PYTHON=/path/to/python pnpm eval:agentdojo --compare results/agentdojo/user-intent
```

Do not tune detectors or rules against benchmark attack text. If a change was informed by looking at benchmark results, say which suites you looked at, and record the new numbers in a new folder under `results/`.

## Common changes

- **A known MCP server is misclassified.** Add or fix its entry in `packages/core/src/tool-catalog.ts`. Match the server by package, image or url, never by anything the server reports. Add a case to `packages/core/src/classifier.test.ts`.
- **A policy rule.** Edit the preset under `policies/`, then add a case to `policies/tests/<preset>.test.yaml` and run `palizade policy test policies/tests/*.yaml`.
- **A new client config format.** See `packages/cli/src/install-config.ts` and `codex-config.ts`; keep users' files intact apart from the servers you change, and write a `.bak` first.

## Pull requests

Keep each pull request to one change, with tests. Note behavior changes under "Upgrading" in `CHANGELOG.md`. CI runs on Windows, macOS and Linux with Node 22 and 24.
