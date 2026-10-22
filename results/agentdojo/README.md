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

## Files

- `baseline/`: first run, before any change made with knowledge of this benchmark. `none` is no defense.
- Later folders, if any, record changes made after looking at results, and say which suites were inspected.
