# Detector Coverage

This page documents the pattern-based `SensitiveDataDetector` in
`packages/detectors/src/sensitive.ts`. It is a high-precision signal for
plaintext and simple secret forms, not a complete data-loss-prevention engine.

Run the local report with:

```bash
pnpm build
pnpm eval:detectors
```

Current measured results on `eval/detector-adversarial/`:

| Corpus | Detected | Total | Rate |
| --- | ---: | ---: | ---: |
| Adversarial secret cases | 24 | 30 | 80.0% |
| Benign false positives | 0 | 25 | 0.0% |

The eval is secret-focused. It runs `SensitiveDataDetector` with secrets enabled
and PII disabled because normal email addresses are intentionally present in the
benign corpus and should not count as secret false positives.

## Capability Table

| Attack type | Detected | Notes |
| --- | --- | --- |
| Plaintext AWS access key | yes | Prefix pattern catches `AKIA` and `ASIA` keys. |
| Plaintext AWS secret assignment | yes | Assignment pattern plus entropy validation. |
| Plaintext OpenAI, GitHub, Slack, Stripe, Google keys | yes | Prefix-specific patterns. |
| Plaintext JWT | yes | Catches compact JWTs and Bearer JWTs. |
| Private key block | yes | Catches PEM-style private key blocks. |
| Secret in JSON string value | yes | Assignment-style pattern catches quoted JSON values. |
| Secret in code comment | yes | Assignment-style pattern catches comment text. |
| Secret in natural language with known prefix | yes | Known key prefixes are detected even in prose. |
| Base64-encoded secret | yes | Long base64 blobs are decoded and rescanned; ordinary base64 text did not false-positive in the benign corpus. |
| Secret in URL query parameter | yes | Secret-like parameter names are checked when values look secret-like. |
| Unicode homoglyph obfuscation | no | Known limitation. The detector does not normalize confusable characters. |
| Split-line or split-token obfuscation | no | Known limitation. Joining arbitrary fragments would raise false-positive risk. |
| JWT with zero-width separators | no | Known limitation. The detector does not strip invisible separators before matching. |
| High-entropy token without a known prefix or assignment context | no | Intentional limitation. Entropy-only detection without context is high-risk for false positives. |

## Limitations

Pattern-based detection catches plaintext and simple obfuscation. Determined
attackers can encode, split, normalize, or paraphrase secrets past this
detector. The egress allowlist and taint/provenance controls are the structural
controls that do not depend on detecting the secret text directly.

PII detection is intentionally simple regex matching for emails, SSNs, credit
cards with Luhn validation, and US-style phone numbers. It is useful for
redaction and policy signals, but it is not jurisdiction-complete PII discovery.
