import { describe, expect, it } from "vitest";
import { parsePolicy } from "./loader.js";
import { SchemaValidationError } from "./errors.js";

describe("schema errors", () => {
  it("reports the YAML path, line and a fix hint for bad policy files", () => {
    const raw = [
      "version: 1",
      "rules:",
      "  - id: block-sink",
      "    when:",
      "      tool_clas: sink",
      "    action: blok"
    ].join("\n");
    let error: unknown;
    try { parsePolicy(raw, "policies/custom.yaml"); } catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(SchemaValidationError);
    const problems = (error as SchemaValidationError).problems;
    expect(problems).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "rules.0.when.tool_clas", line: 5, hint: "Did you mean 'tool_class'? Otherwise remove the key." }),
      expect.objectContaining({ path: "rules.0.action", line: 6, hint: expect.stringContaining("\"block\"") })
    ]));
    expect((error as Error).message).toMatch(/^Invalid policies\/custom\.yaml \(2 problems\):/u);
    expect((error as Error).message).toContain("rules.0.when.tool_clas (line 5): Unknown key 'tool_clas'");
  });

  it("reports YAML syntax errors with a line number", () => {
    expect(() => parsePolicy("version: 1\nrules:\n  - id: [unclosed\n", "p.yaml")).toThrow(/line \d+.*YAML syntax error/su);
  });

  it("parses a valid policy unchanged", () => {
    const policy = parsePolicy("version: 1\nrules:\n  - id: ok\n    when: { tool_class: sink }\n    action: block\n");
    expect(policy.rules[0]).toMatchObject({ id: "ok", action: "block", when: { tool_class: "sink" } });
    expect(policy.defaults).toEqual({ action: "allow", on_error: "block" });
  });
});
