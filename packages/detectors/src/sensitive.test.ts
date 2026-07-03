import { describe, expect, it } from "vitest";
import { hasPiiLabel, hasSecretLabel, maskSensitiveText, SensitiveDataDetector } from "./sensitive.js";

describe("SensitiveDataDetector", () => {
  it("detects common secret and PII patterns with spans", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true },
      pii: { enabled: true }
    });
    const result = detector.detect("token=sk-testsecret000000000000000000 and ssn 123-45-6789");

    expect(result.score).toBeGreaterThanOrEqual(0.75);
    expect(hasSecretLabel(result.labels)).toBe(true);
    expect(hasPiiLabel(result.labels)).toBe(true);
    expect(maskSensitiveText("token=sk-testsecret000000000000000000 and ssn 123-45-6789", result.spans)).not.toContain("123-45-6789");
  });

  it("honors disabled detector families", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: false },
      pii: { enabled: true, ssn: true, email: false }
    });
    const result = detector.detect("token=sk-testsecret000000000000000000 and jane@example.test");

    expect(hasSecretLabel(result.labels)).toBe(false);
    expect(result.labels).not.toContain("pii:email");
  });

  it("does not flag ordinary prose or invalid card-shaped numbers", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true },
      pii: { enabled: true }
    });

    expect(detector.detect("The release notes mention tokens, keys, and credentials as concepts only.").labels).toEqual([]);
    expect(detector.detect("Card-like placeholder 4111 1111 1111 1112 should fail Luhn.").labels).not.toContain("pii:credit-card");
  });
});
