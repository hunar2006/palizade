import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import YAML from "yaml";
import { upgradePolicyText } from "./policy-upgrade.js";

const preset = readFileSync("policies/default.yaml", "utf8");

describe("upgradePolicyText", () => {
  it("adds missing preset rules in order and keeps the user's own rules and comments", () => {
    const doc = YAML.parseDocument(preset);
    const rules = doc.get("rules") as YAML.YAMLSeq;
    const drop = new Set(["allow-following-copied-link", "approve-credential-change-after-untrusted"]);
    rules.items = rules.items.filter((item) => !drop.has(String((item as YAML.YAMLMap).get("id"))));
    rules.items.splice(3, 0, doc.createNode({ id: "my-own-rule", when: { direction: "request", tool: "deploy" }, action: "require_approval" }));
    const old = `# my notes\n${doc.toString()}`;

    const result = upgradePolicyText(old, preset);
    expect(result.added).toEqual(["allow-following-copied-link", "approve-credential-change-after-untrusted"]);
    expect(result.text.startsWith("# my notes")).toBe(true);
    const ids = (YAML.parse(result.text) as { rules: Array<{ id: string }> }).rules.map((rule) => rule.id);
    const shippedIds = (YAML.parse(preset) as { rules: Array<{ id: string }> }).rules.map((rule) => rule.id);
    expect(ids.filter((id) => id !== "my-own-rule")).toEqual(shippedIds);
    expect(ids).toContain("my-own-rule");
    expect(upgradePolicyText(result.text, preset).added).toEqual([]);
  });

  it("reports rules the user changed without touching them", () => {
    const edited = preset.replace("reason: Destination came from untrusted content.", "reason: Mine.");
    const result = upgradePolicyText(edited, preset);
    expect(result.differs).toContain("block-tainted-destination");
    expect(result.text).toBe(edited);
  });
});
