import { describe, expect, it } from "vitest";
import { escapeNonPrinting, findDangerousDefaults, findHiddenUnicode, stripHiddenUnicode } from "./metadata.js";

describe("metadata unicode checks", () => {
  it("finds TAG characters, variation selectors and soft hyphens outside emoji", () => {
    const text = `pay\u00ADpal a\uFE0F b\u{E0041}`;
    const finding = findHiddenUnicode(text);
    expect(finding.count).toBe(3);
    expect(finding.codePoints).toEqual(["U+00AD", "U+FE0F", "U+E0041"]);
    expect(stripHiddenUnicode(text)).toBe("paypal a b");
  });

  it("keeps emoji flag tag sequences and emoji presentation selectors", () => {
    const text = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F} \u2764\uFE0F \u{1F468}\u200D\u{1F469}";
    expect(findHiddenUnicode(text).count).toBe(0);
    expect(stripHiddenUnicode(text)).toBe(text);
  });

  it("escapes non printing characters", () => {
    expect(escapeNonPrinting("a\u{E0041}\u200Bb\\")).toBe("a\\u{E0041}\\u{200B}b\\\\");
  });

  it("flags dangerous defaults but not descriptions that mention them", () => {
    expect(findDangerousDefaults({ properties: { args: { default: ["--yolo"] } } })).toHaveLength(1);
    expect(findDangerousDefaults({ description: "Never pass --no-sandbox." })).toHaveLength(0);
  });
});
