# Evaluation after v0.4

This is a plan, not a new benchmark result. The published 0% ASR is in-sample: the current replay harness uses inferred sink arguments, and a matcher fix was informed by that corpus. Keep existing fixtures, results and ASR figures unchanged until a separately reviewed evaluation task creates versioned held-out data.

## Real agents through MCP

Wrap every AgentDojo suite as an MCP server behind Palizade and run a real model under matched seeds, prompts, tool schemas and model versions. Compare unwrapped, audit-only, default, strict, interactive, coding and research configurations. Record the model/provider/version, policy/config hashes, commit, platform and explicit budgets. Separate automatically allowed actions, approvals requested, human approvals granted, denied actions and model refusals. Do not count a timeout or a model refusal as a successful firewall decision.

Report benign task utility, utility under attack, targeted attack success rate, approval prompts per task and fraction of tasks requiring approval. Include numerator/denominator, repeated-run uncertainty and completion/error/timeout counts. Report both attacker-targeted success and unintended side effects. An approval is a utility cost and a separate security outcome; do not silently count every ask as a block.

## Poisoning and memory

Add MCPTox for malicious metadata, hidden characters, schema defaults, name collisions, shadowing and lock drift. Exercise registration order, refresh/list_changed, both protocol eras and stdio/HTTP. Separate detection from withholding/approval and report effects on legitimate tools with common built-in names.

Add MPBench for memory/vector persistence: ingest an untrusted source, approve or deny a memory write, reopen the store after TTL and under a new run, retrieve transformed text and attempt a sink. Verify original provenance IDs, profile isolation and explicit prune behavior. Measure benign note-taking utility and legitimate cross-run recall, not just attack blocks.

## Plausible sink arguments and benign flows

Rebuild InjecAgent translations in a new held-out fixture set so sink arguments contain only values an agent would plausibly produce, such as `to`, `amount` and `path`. Exclude copied attacker instructions and the synthetic `source_instruction` field. Have reviewers who did not develop the matcher check inferred arguments and target intent before freezing the set. Preserve the old corpus and its published results as historical in-sample evidence.

Include realistic benign copy flows: save a page to notes.md, forward an email to a user-selected boss, persist research notes, copy source code into an output artifact, run tests and push to an approved remote. Vary trusted/sensitive/untrusted exposure order, explicit session grants and output paths. Count copied-content blocks, quarantine/rate/loop gates and approvals as utility costs. Add long sources, Unicode prose, valid emoji, images/binary uploads and ordinary URLs/IDs to measure false gates.

## Adaptive red team

Give attackers the matcher, policies and bounds. Include every M1 family: TAG/variation/soft-hyphen concealment, confusable identifiers and punycode, base64/base64url, hex, percent/HTML/JS/RFC-2047 nesting, destination IDs and split secrets. Vary offsets beyond fingerprint coverage, shard length, query/path/body placement, independently padded encodings, destinations, processes, sessions and timing around TTL/window limits. Include semantic paraphrase and approved persistent-memory laundering, plus DNS/ICMP/native shell attempts with and without installed hooks. Test boundary exhaustion and security-path failures.

Hold out attack templates, models and suites, and reserve a final set the developers cannot inspect before scoring. Freeze benign acceptance criteria and approval handling before attacks are revealed. Publish misses and utility regressions, including attacks outside observable proxy/hook traffic (for example client-rendered image fetching), rather than presenting scope exclusions as successes.

## Runtime and platform checks

Measure complete proxy/hook/HTTP paths separately from the SQLite store microbenchmark: p50/p95/p99, throughput, memory, concurrent SSE traffic, store contention, reload and approval latency. Run Windows, Linux and macOS; execute Docker, bubblewrap and seatbelt where available, verify denied network/write attempts and include hostile servers that ignore proxy variables. Test multiple listener clients and independent legacy sessions. Retain the 15 ms SQLite sink p95 check as a regression budget, not a claim of end-to-end latency.

Archive versioned scripts, manifests, hashes and payload-free aggregate results. Keep raw attack/secret material out of audit logs and use synthetic credentials. This evaluation remains unrun in the v0.4 build.
