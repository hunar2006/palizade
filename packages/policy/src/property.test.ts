import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { SchemaValidationError } from "./errors.js";
import { evaluatePolicy } from "./evaluator.js";
import { parsePolicy } from "./loader.js";

const yamlish = fc.array(fc.constantFrom("version: 1\n", "rules:\n", "  - ", "id: a", "action: allow", "action: nope", "when: ", "{ ", " }", "[", "]", ", ", "&x ", "*x", "!!binary ", "? ", ": ", "- ", "'", "\"", "#c\n", "\t", "\n", "  ", "direction: request", "argument_regex: '('", "<<: *x", "%YAML 1.2\n", "---\n", "..."), { maxLength: 40 }).map((parts) => parts.join(""));

describe("policy YAML loader", () => {
  it("either returns a policy or throws SchemaValidationError, for any input", () => {
    fc.assert(fc.property(fc.oneof(yamlish, fc.string({ maxLength: 200 })), (raw) => {
      try { parsePolicy(raw); }
      catch (error) { expect(error).toBeInstanceOf(SchemaValidationError); }
    }), { numRuns: 500 });
  });

  it("reports an alias bomb as an invalid file (was a bare ReferenceError)", () => {
    let raw = "a: &a [x,x,x,x,x,x,x,x,x]\n";
    for (let index = 1; index < 10; index += 1) raw += `${String.fromCharCode(97 + index)}: &${String.fromCharCode(97 + index)} [${Array(9).fill(`*${String.fromCharCode(96 + index)}`).join(",")}]\n`;
    expect(() => parsePolicy(raw)).toThrow(SchemaValidationError);
    expect(() => parsePolicy("[".repeat(100000) + "]".repeat(100000))).toThrow(SchemaValidationError);
  });
});

const preset = (name: string) => parsePolicy(readFileSync(resolve(import.meta.dirname, `../../../policies/${name}.yaml`), "utf8"), name);
const selfRule = (name: string) => preset(name).rules.find((rule) => rule.id === "approve-palizade-self-change")!.when!.argument_regex!;
// The rule as first shipped, before its two scans were pinned to the first match in each segment.
const OLD_BRANCHES = String.raw`\b(?:npm|pnpm|yarn|bun)\b[^;&|\n]*\b(?:uninstall|remove|rm|r|un|unlink)\s[^;&|\n]*\bpalizade\b|\b(?:rm|rmdir|mv|cp|sed|perl|python3?|node|ruby|truncate|tee|dd|shred|unlink|ln|chmod|chown|chattr|touch|install|del|erase|remove-item|move-item|set-content|out-file|clear-content)\b[^;&|\n]*(?:\.palizade\b|palizade\.(?:ya?ml|allow\.ya?ml|lock)\b|\.claude[\\/]settings(?:\.local)?\.json|\.claude\.json|\.mcp\.json|\.cursor[\\/](?:hooks|mcp)\.json|\.codex[\\/](?:config\.toml|hooks\.json)|\.gemini[\\/]settings\.json|claude_desktop_config\.json)`;

describe("self protection rule", () => {
  const current = new RegExp(selfRule("default"), "iu");
  const palizadeBranch = selfRule("default").split("|(?:^|[;&|\\n])(?=(?<pm>")[0]!;
  const old = new RegExp(`${palizadeBranch}|${OLD_BRANCHES}`, "iu");
  const command = fc.array(fc.constantFrom("rm ", "-rf ", "npm ", "pnpm ", "uninstall ", "remove ", "r ", "palizade ", "palizade.yaml", ".palizade/", "x ", "&& ", "; ", "| ", "\n", "sed -i ", "cat ", ".claude/settings.json", "status", "allow ", "npx ", "A=1 ", "sudo "), { maxLength: 14 }).map((parts) => parts.join(""));

  it("is the same rule in default, strict and coding-agent", () => {
    expect(selfRule("strict")).toBe(selfRule("default"));
    expect(selfRule("coding-agent")).toBe(selfRule("default"));
  });

  it("matches exactly what the first version matched", () => {
    fc.assert(fc.property(command, (text) => { expect(current.test(text)).toBe(old.test(text)); }), { numRuns: 2000 });
  });

  it("evaluates a 1 MB shell command quickly (was seconds at 32 KB)", () => {
    const policy = preset("default");
    for (const unit of ["rm ", "npm ", "npm uninstall ", "palizade ", "a=b "]) {
      const start = performance.now();
      evaluatePolicy(policy, { direction: "request", method: "tools/call", tool_class: "sink", argument_roles: ["shell_command"], argument_text: unit.repeat(Math.ceil(1024 * 1024 / unit.length)) });
      expect(performance.now() - start).toBeLessThan(5000);
    }
  });
});
