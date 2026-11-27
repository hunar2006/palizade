# Live model AgentDojo results

This directory stores results produced by live local-model AgentDojo runs from [`eval/agentdojo/live/colab.ipynb`](../../eval/agentdojo/live/colab.ipynb).

No live model run has been executed yet. Each completed run writes a subdirectory `results/agentdojo-live/<run-id>/` containing:

- `summary.md`: human-readable tables (held-out `travel` separated from inspected `workspace + slack + banking`, per-suite breakdown, approval bounds, token/time totals, full-benchmark projection arithmetic, and methodological caveats)
- `summary.json`: structured JSON of the same metrics and projections
- `summary.csv`: per-(defense, suite) numerator/denominator table
- `manifest.json`: model ID, vLLM version, GPU name, pinned repo commit SHA, decoding parameters, and package pins
- `episodes.jsonl`: append-only per-episode records with proposed vs executed calls, tokens, and wall-clock time
