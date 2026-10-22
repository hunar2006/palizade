import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadPolicyFile, parsePolicy } from "./loader.js";
import { parsePolicyTests, runPolicyTests } from "./test-cases.js";

const testsDir = resolve(import.meta.dirname, "../../../policies/tests");

describe("policy test files", () => {
  for (const file of readdirSync(testsDir).filter((name) => name.endsWith(".test.yaml"))) {
    it(`${file} passes`, async () => {
      const path = join(testsDir, file);
      const tests = parsePolicyTests(readFileSync(path, "utf8"), path);
      const results = runPolicyTests(await loadPolicyFile(resolve(dirname(path), tests.policy!)), tests);
      expect(results.filter((result) => !result.passed)).toEqual([]);
    });
  }

  it("reports a failing case with expected and actual decisions", () => {
    const policy = parsePolicy("version: 1\ndefaults: { action: allow, on_error: block }\nrules:\n  - id: no-sinks\n    when: { tool_class: sink }\n    action: block\n");
    const tests = parsePolicyTests("cases:\n  - name: sinks allowed\n    context: { direction: request, tool_class: sink }\n    expect: { action: allow }\n  - name: sources pass\n    context: { direction: request, tool_class: source }\n    expect: { action: allow, not_rule: no-sinks }\n", "t.yaml");
    expect(runPolicyTests(policy, tests)).toEqual([
      { name: "sinks allowed", passed: false, expected: "allow", actual: "block, rule no-sinks" },
      { name: "sources pass", passed: true, expected: "allow, not rule no-sinks", actual: "allow, default" }
    ]);
  });

  it("rejects misspelled context fields", () => {
    expect(() => parsePolicyTests("cases:\n  - name: typo\n    context: { direction: request, tainted: true }\n    expect: allow\n", "t.yaml")).toThrow(/tainted/u);
  });
});
