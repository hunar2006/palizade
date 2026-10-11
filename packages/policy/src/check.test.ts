import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkPolicy } from "./check.js";

const presetsDir = fileURLToPath(new URL("../../../policies", import.meta.url));

describe("policy check", () => {
  it("flags unreachable rules, impossible conditions and unknown references", () => {
    const raw = [
      "version: 1",
      "rules:",
      "  - id: never",
      "    when: { detector_score_gte: 0.9, detector_score_lt: 0.5, labels_any: [] }",
      "    action: block",
      "  - id: bad-regex",
      "    when: { argument_regex: '(unclosed' }",
      "    action: block",
      "  - id: wrong-refs",
      "    when: { server: gihtub, tool: create_isue }",
      "    action: block",
      "  - id: typo-tool",
      "    when: { server: github, tool: create_isue }",
      "    action: block",
      "  - id: allow-everything",
      "    action: allow",
      "  - id: after-catch-all",
      "    when: { tool_class: sink }",
      "    action: block",
      "  - id: never",
      "    action: block"
    ].join("\n");
    const { findings } = checkPolicy(raw, "custom.yaml", { servers: ["github"], toolsByServer: { github: ["create_issue", "list_issues"] } });
    const summary = findings.map((finding) => `${finding.level}:${finding.check}:${finding.path}`);
    expect(summary).toEqual(expect.arrayContaining([
      "warning:impossible:rules.0.when.labels_any",
      "warning:impossible:rules.0.when.detector_score_lt",
      "error:impossible:rules.1.when.argument_regex",
      "warning:unknown_reference:rules.2.when.server",
      "warning:unknown_reference:rules.3.when.tool",
      "warning:unreachable:rules.5",
      "warning:unreachable:rules.6",
      "warning:duplicate_id:rules.6.id"
    ]));
    expect(summary).not.toContain("warning:unreachable:rules.4");
    expect(findings.find((finding) => finding.path === "rules.5")).toMatchObject({ line: 17, ruleId: "after-catch-all" });
  });

  it("reports schema problems and unknown keys as errors", () => {
    const { policy, findings } = checkPolicy("version: 1\nrules:\n  - id: x\n    when: { taintt: true }\n    action: block\n", "p.yaml");
    expect(policy).toBeUndefined();
    expect(findings).toEqual([expect.objectContaining({ level: "error", check: "unknown_key", path: "rules.0.when.taintt", line: 4, hint: "Did you mean 'taint'? Otherwise remove the key." })]);
  });

  it("finds nothing wrong in the shipped presets", () => {
    for (const file of readdirSync(presetsDir).filter((name) => name.endsWith(".yaml"))) {
      const { findings } = checkPolicy(readFileSync(join(presetsDir, file), "utf8"), file);
      expect({ file, findings }).toEqual({ file, findings: [] });
    }
  });
});
