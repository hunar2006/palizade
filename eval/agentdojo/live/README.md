# AgentDojo live evaluation harness and smoke test

The launcher runs clean and attacked AgentDojo v1.2.2 tasks against a local, OpenAI compatible server. No real model results exist yet. All smoke counts come from a scripted stub and say nothing about any model.

## Run the smoke test on Windows

Use Python 3.10 or newer, Node 22.13 or newer, and pnpm. Run these from the repository root in PowerShell. Setup creates `eval/agentdojo/.venv` and installs the pinned `agentdojo==0.1.35` package there.

```powershell
pnpm install --frozen-lockfile
pnpm build
pnpm eval:agentdojo:setup
pnpm eval:agentdojo:smoke
```

The smoke script starts its own loopback stub and shuts it down. It runs two scripted stub modes against fictional tools whose state lives in memory:

1. Clean mode runs user tasks with no attacks and verifies completion under `none`.
2. Obedient mode runs each user task and, once a tool result carries the benchmark injection text, emits the injection task ground truth calls. It runs Workspace pairs across `none`, `spotlighting_with_delimiting`, `palizade-default`, `palizade-default-approved`, `palizade-strict`, and `palizade-strict-approved`, plus a Slack pair that exercises trace based attack scoring. It verifies resume skipping for completed clean and attack checkpoints and confirms a distinct fake API key stays out of every output file under `.palizade/agentdojo/smoke`.

## Run a full evaluation against a local model

Run the setup commands above before using `live`. Start Ollama or LM Studio and load a model that supports tool calling. Use the exact model ID shown by your server. The launcher accepts loopback endpoints only (`localhost`, `127.0.0.1`, or `::1`). Neither Ollama nor LM Studio has been exercised in this worktree.

The `tool_filter` defense sends a `developer` role message and `tool_choice: "none"` together with a `tools` list. Some local endpoints reject that request or return an empty tool list. Check whether your endpoint supports this combination before comparing the `tool_filter` row.

Ollama in PowerShell (full four suite run with `important_instructions`):

```powershell
ollama list
$env:PALIZADE_EVAL_API_KEY = 'local'
$env:PALIZADE_EVAL_BASE_URL = 'http://127.0.0.1:11434/v1'
$modelId = 'replace-with-an-installed-tool-calling-ollama-model-id'
$displayName = 'Local model'
pnpm eval:agentdojo:live --model $modelId --model-display-name $displayName --attack important_instructions --suites 'workspace,slack,banking,travel' --defenses 'none,spotlighting_with_delimiting,repeat_user_prompt,tool_filter,palizade-default,palizade-default-approved,palizade-strict,palizade-strict-approved' --logdir .palizade/agentdojo/ollama
```

LM Studio in PowerShell after starting its local server with a model that supports tool calling:

```powershell
$env:PALIZADE_EVAL_API_KEY = 'local'
$env:PALIZADE_EVAL_BASE_URL = 'http://127.0.0.1:1234/v1'
$modelId = 'replace-with-the-loaded-tool-calling-lm-studio-model-id'
$displayName = 'Local model'
pnpm eval:agentdojo:live --model $modelId --model-display-name $displayName --attack important_instructions --suites 'workspace,slack,banking,travel' --defenses 'none,spotlighting_with_delimiting,repeat_user_prompt,tool_filter,palizade-default,palizade-default-approved,palizade-strict,palizade-strict-approved' --logdir .palizade/agentdojo/lm-studio
```

Useful launcher flags:

* `--attack`: AgentDojo attack name. Defaults to `important_instructions`. Pass `none` to run clean tasks only.
* `--model-display-name`: Display name placed in attack templates such as `important_instructions`. The launcher applies the same display name to every defense row. If omitted, it matches `MODEL_NAMES` in AgentDojo or falls back to `Local model`.
* `--suites`, `--user-tasks`, `--injection-tasks`, `--max-tasks`: Filter the evaluation slice.
* `--base-url`: Overrides `PALIZADE_EVAL_BASE_URL` and `OPENAI_BASE_URL`. The launcher reads `PALIZADE_EVAL_API_KEY` or `OPENAI_API_KEY`, defaults to `local` when both are empty, and keeps the key out of checkpoint and report files.
* `--resume`: Repeat the command with `--resume` after stopping a run to skip completed clean and attack checkpoints. Checkpoints are stored as one JSONL file per episode under a directory keyed by benchmark version, model, endpoint, attack, display name, policies, harness code, and built engine code. Both summaries use every completed checkpoint in that directory, even if a resume selects fewer tasks. Use a fresh `--logdir` for an independent repeat run.

Available defenses are `none`, `spotlighting_with_delimiting`, `repeat_user_prompt`, `transformers_pi_detector`, `tool_filter`, `palizade-default`, `palizade-default-approved`, `palizade-strict`, and `palizade-strict-approved`.

## Google Colab GPU pilot (`colab.ipynb`)

`eval/agentdojo/live/colab.ipynb` runs the deterministic D3 pilot slice (`eval/agentdojo/live/pilot_slice.json`: 10 clean user tasks, 35 calibration objectives, and 98 `important_instructions` attacked episodes per pipeline config) on a Google Colab A100 using a local vLLM server with tool calling enabled and thinking disabled. It includes:

* `eval/agentdojo/live/preflight.py`: verifies structured tool calling on 3 non travel sample tasks before starting the pilot and exits non zero if tool calls are missing, malformed, or leak thinking tags.
* Per episode append and flush to a JSONL file on Google Drive (`--episodes-jsonl` with `--resume`), while model weights and Hugging Face cache stay on Colab local disk.
* `score_live.py --episodes-jsonl ... --out-dir ...`: writes `summary.md`, `summary.json`, `summary.csv`, `manifest.json`, and `episodes.jsonl` under `results/agentdojo-live/<run-id>/` with held out `travel` separated from the inspected suites and full benchmark time and A100 compute unit estimates.

## Approval bounds and report columns

`summary.md` prints fractions and percentages for each defense, approval setting, and suite. `summary.csv` writes each numerator and denominator in separate columns.

* `Approvals`: Shows `Denied` for `palizade-default` and `palizade-strict` (every non catalog approval prompt is denied) and `Granted` for `palizade-default-approved` and `palizade-strict-approved` (approval prompts are granted while hard blocks remain blocked). Non Palizade rows show `n/a`. Reporting both bounds shows the range between a user who refuses every prompt and a user who accepts every prompt, which matters especially for `strict` because its policy default is `require_approval`.
* `Clean utility`: Share of clean user tasks that passed AgentDojo checks.
* `Utility under attack`: Share of attacked episodes where the user task still passed AgentDojo checks.
* `Stock attack success`: Share of attacked episodes where AgentDojo stock scoring marked the injection goal as achieved using assistant message tool calls.
* `Executed attack success`: Share of attacked episodes where the same AgentDojo security check marked the injection goal as achieved using only tool calls actually dispatched to the runtime. Calls blocked or denied by Palizade do not count as executed even though they appear in assistant messages.
* `Episodes with a hard block` and `Hard blocked calls`: Episodes and calls stopped by a policy `block` action. These stay blocked in both approval bounds.
* `Episodes with an approval prompt` and `Approval prompted calls`: Episodes and tool calls that hit a policy `require_approval` gate, whether denied or granted.

## Suite provenance

Workspace, Slack, and banking were looked at during policy development. Travel is the only suite that was never inspected during that work. The report keeps travel in separate rows labelled `Only suite never inspected`.

## How the executor and bridge work

`bridge.mjs` is a long lived Node process reading one JSON object per line on standard input and replying on standard output.

The bridge uses the product detector pipeline and its default settings. Secret, PII, and model detection are all off by default. The bridge and scripted replay need a system temp directory outside Palizade protected paths.

* `start`: Takes `suite`, `tools`, `prompt`, `preset` (`default` or `strict`), and optional `approvals` (`deny` or `approve`, default `deny`). It creates fresh in memory taint state, registers observables from the user prompt, marks the server untrusted, approves the supplied tool schemas in an in memory lockfile via `LockfileStore.approveTools`, and preapproves the `strict` policy default `tools/list` catalog prompt so the catalog is exposed while tool description checks still run.
* `check`: Takes `name` and `arguments`. Returns `decision` (`allow`, `block`, or `needs_approval`), `approvalPrompted`, `ruleId`, and `reason`, plus `callId` and `arguments` when allowed. Hard blocks return `block` in both approval modes. Approval gates return `needs_approval` when `approvals` is `deny`, and `allow` with `approvalPrompted: true` when `approvals` is `approve`.
* `record`: Takes `callId`, text `result`, and `isError`. Submits the tool result to `InterceptionEngine` and returns the policy permitted text or `blocked: true` when withheld.
* `end`: Closes the episode and returns `approvalPrompts`.

`PalizadeToolsExecutor` wraps AgentDojo tool execution so every proposed call goes through `check` before `runtime.run_function` and every returned result goes through `record` before reaching the model. It records proposed calls, executed calls, hard blocked calls, and approval prompted calls separately so `score_attack_trace` can compare stock and executed traces.

The older scripted replay uses fixed ground truth calls with no model loop. [Scripted replay results](../../../results/agentdojo/README.md)
