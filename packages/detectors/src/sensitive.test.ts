import { describe, expect, it } from "vitest";
import { hasPiiLabel, hasSecretLabel, maskSensitiveText, SensitiveDataDetector } from "./sensitive.js";

describe("SensitiveDataDetector", () => {
  it("detects common secret and PII patterns with spans", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true },
      pii: { enabled: true }
    });
    const result = detector.detect("token=sk-FAKETESTSECRET00000000000000 and ssn 123-45-6789");

    expect(result.score).toBeGreaterThanOrEqual(0.75);
    expect(hasSecretLabel(result.labels)).toBe(true);
    expect(hasPiiLabel(result.labels)).toBe(true);
    expect(maskSensitiveText("token=sk-FAKETESTSECRET00000000000000 and ssn 123-45-6789", result.spans)).not.toContain("123-45-6789");
  });

  it("honors disabled detector families", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: false },
      pii: { enabled: true, ssn: true, email: false }
    });
    const result = detector.detect("token=sk-FAKETESTSECRET00000000000000 and jane@example.test");

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

  it("decodes base64 candidates and rescans decoded secret patterns", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true }
    });
    const encoded = Buffer.from("AKIAIOSFODNN7EXAMPLE").toString("base64");
    const result = detector.detect(`Encoded credential ${encoded}`);

    expect(hasSecretLabel(result.labels)).toBe(true);
    expect(result.labels).toContain("secret:aws-access-key-id");
    expect(result.spans?.[0]?.label).toContain("secret:base64");
  });

  it("detects secret-looking URL query parameters without flagging placeholders", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true }
    });

    expect(detector.detect("https://example.com/save?api_key=sk-FAKETESTSECRET1234567890abcdef").labels).toContain("secret:url-query");
    expect(detector.detect("https://example.com/setup?api_key=your-key-here").labels).toEqual([]);
  });

  it("does not flag environment references or ordinary base64 text as secrets", () => {
    const detector = new SensitiveDataDetector({
      secrets: { enabled: true }
    });

    expect(detector.detect("// api_key = process.env.API_KEY").labels).toEqual([]);
    expect(detector.detect("token = \"set-this-in-production\"").labels).toEqual([]);
    expect(detector.detect("Example base64 SGVsbG8gd29ybGQgdGhpcyBpcyBhIG5vdGUu").labels).toEqual([]);
  });
});
