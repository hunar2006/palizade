# Palizade InjecAgent ASR Summary

| Category | N | ASR (off) | ASR (default) | ASR (strict) |
|---|---:|---:|---:|---:|
| Direct injection | 15 | 100% | 0% | 0% |
| Indirect/tool injection | 25 | 100% | 0% | 0% |
| Encoded/obfuscated | 10 | 100% | 0% | 0% |
| Total attacks | 50 | 100% | 0% | 0% |
| Benign FP rate | 25 | 0% | 0% | 0% |

Replay verification sample: 10; mismatches: 0.


## Final Caption

Derived from InjecAgent (Zhan et al., ACL 2024 Findings, github.com/uiuc-kang-lab/InjecAgent), translated to MCP tool-call format, seed=424242, stratified sample (see NOTES.md for full methodology). Not a run of the original benchmark. Encoded/obfuscated cases apply base64/hex transforms to real InjecAgent instructions programmatically; ASR(off) for this category was 100%, see NOTES.md for validity caveat if below 100%. Palizade blocks on taint provenance - cases where the agent complies but tainted content hits a sink. Of 225 total runs, 0 were classified 'model refused' (no audit-log rule fired) versus 100 'Palizade blocked' (audit-log rule fired), verified via 10% programmatic spot-check with 0 mismatches. 57 sink-call arguments across 6 fixtures were inferred rather than extracted verbatim - see manifest.csv and NOTES.md for details. The two attacks that previously survived were traced to a substring-alignment bug in taint fingerprinting, found by inspecting this corpus, so these ASR figures are in-sample; see NOTES.md Task 1.

## Task Checks

- PASS: Task 1 checked indirect fixtures with attack_success under both default and strict; found 0 fixture(s).
- PASS: Task 2 checked encoded/obfuscated ASR(off); found 10/10 (100%).
- PASS: Task 3 checked 6 low-confidence fixtures; placeholder issues found: 0.
- PASS: Task 4 reviewed all 25 benign fixtures and scanned contacts/names for manual review candidates.

## Human Review

78 items flagged for review, listed individually in NOTES.md Task 4: 17 low-value benign fixtures (no sink call, so they cannot produce a false positive), plus 51 email, 4 phone and 6 name values carried verbatim from the upstream InjecAgent corpus.
