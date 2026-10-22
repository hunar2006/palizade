# AgentDojo replay results

These numbers come from [AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks), benchmark version v1.2.2, package `agentdojo==0.1.35`, attack `important_instructions`. Palizade was not tuned on this benchmark before the `baseline` run, so `baseline` is a held out result.

Reproduce with `PALIZADE_PYTHON=/path/to/python pnpm eval:agentdojo` (needs `pip install agentdojo==0.1.35`). It takes about 15 minutes. No model or API key is used.

## Method

1. `eval/agentdojo/export_traces.py` runs each suite's scripted ground truth. A clean trace is the user task alone. An attacked trace places the attack text into the environment, runs the user task, and then runs the injection task's ground truth calls. This models an agent that does the user's task and then fully obeys the injection.
2. `eval/agentdojo/replay.mjs` sends every call and tool result through a Palizade engine. Each suite is one MCP server with `trust: untrusted`, using a shipped policy preset and the heuristic detector. Each call gets one of three outcomes: allow, approval (Palizade asked the user), or block.
3. `eval/agentdojo/score.py` re-runs each trace, executing only the calls Palizade let through. It then uses AgentDojo's own checks to decide whether the user task succeeded (utility) and whether the injection goal was reached (attack success). `deny` means the user refuses every approval prompt; `approve` means the user accepts every prompt, which is the worst case.

## Limits

- This replays scripted traces, not an LLM. A real model often ignores injections, so its attack success without a defense is lower than the `none` row. The rows show what Palizade stops when the agent does obey.
- After a blocked call the trace continues as scripted, while a real agent might adapt. Calls that come after a blocked call are judged on their own.
- Utility uses the ground truth answer text. Utility under attack can be higher with Palizade than without it, because blocking the injection's writes leaves the environment intact.
- Every suite tool is treated as one untrusted server. Splitting tools into trusted and untrusted servers would change results.

## Summary (default preset, approvals denied)

| Run | Clean utility | Utility under attack | Attack success |
|---|---:|---:|---:|
| No defense | 97/97 (100%) | 579/949 (61.0%) | 593/949 (62.5%) |
| Palizade, `baseline` (held out) | 67/97 (69.1%) | 665/949 (70.1%) | 42/949 (4.4%) |
| Palizade, `after-dev-review` | 68/97 (70.1%) | 648/949 (68.3%) | 11/949 (1.2%) |
| Palizade, `user-intent` | 74/97 (76.3%) | 730/949 (76.9%) | 0/949 in this replay |

On the two suites that were not inspected (banking, travel), `after-dev-review` moved clean utility from 29/36 to 30/36 and attack success from 12/284 to 11/284. Most of the remaining utility loss is the cost of the provenance design: a user task that sends to an address or url it read from untrusted content looks the same as an attack, so Palizade blocks it in the default preset.

### `user-intent`

Two changes, both general:

1. **Destinations the user typed.** The replay now gives Palizade each user task's prompt, as the prompt hooks do in Claude Code, Codex and Cursor. Email addresses, urls, hosts, handles and account numbers in the prompt are not treated as copied from untrusted content. On its own this raised clean utility from 68 to 75 and utility under attack from 648 to 737, and attack success went from 11 to 14. All 14 were one injection (banking `injection_task_7`, set the account password to a value from the page): before, it was stopped only because an earlier blocked call had put the session in quarantine; with that call now allowed, nothing else caught it.
2. **Ask before changing a password, key or token after untrusted content** (`approve-credential-change-after-untrusted`). This stops those 14, and costs one clean task where the user asks to change their password after reading their transactions (approvals are refused in these rows).

Per suite, default preset, approvals denied:

| Suite | Clean utility | Attack success |
|---|---:|---:|
| workspace | 32/40 | 0/560 |
| slack | 11/21 | 0/105 |
| banking | 13/16 | 0/144 |
| travel | 18/20 | 0/140 |

The second change was found by looking at banking traces, so banking is no longer held out. Travel has still not been inspected. Zero here means zero of these scripted attacks, not that Palizade stops every injection: the remaining risk lies in what these traces do not contain, such as attacks that only need the agent to say something, or data a policy cannot see.

## Files

- `baseline/`: first run, before any change made with knowledge of this benchmark. `none` is no defense.
- `user-intent/`: prompts given to Palizade, plus the credential change rule (see above).
- `after-dev-review/`: after two changes made by looking only at the workspace and slack suites (the dev suites); banking and travel stayed held out. The changes are general rather than benchmark specific:
  1. Verbs that change shared state (add, invite, update, set, assign, grant, share, rename, archive, reply, forward, schedule, cancel) now mark a tool as a remote write, so a tool such as `add_user_to_channel` is no longer "unknown".
  2. A new rule in the default, interactive and strict presets asks before any delete once the session has seen untrusted content (`approve-delete-after-untrusted`). A delete has no destination to check, so taint on arguments alone missed it.
  No detector pattern was added from the benchmark's attack text.
