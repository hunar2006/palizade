import { describe, expect, it } from "vitest";
import { promptGuardMaliciousScore } from "./promptguard2.js";

describe("promptGuardMaliciousScore", () => {
  it("maps PromptGuard LABEL_0 to benign probability", () => {
    expect(promptGuardMaliciousScore([{ label: "LABEL_0", score: 0.99 }])).toBeCloseTo(0.01);
  });

  it("maps PromptGuard LABEL_1 to malicious probability", () => {
    expect(promptGuardMaliciousScore([{ label: "LABEL_1", score: 0.97 }])).toBeCloseTo(0.97);
  });

  it("maps explicit malicious and benign labels", () => {
    expect(promptGuardMaliciousScore([{ label: "MALICIOUS", score: 0.88 }])).toBeCloseTo(0.88);
    expect(promptGuardMaliciousScore([{ label: "BENIGN", score: 0.88 }])).toBeCloseTo(0.12);
  });
});
