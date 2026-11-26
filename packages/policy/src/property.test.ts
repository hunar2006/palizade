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
// The first version's file and package changes, kept as coverage for real command stages.
const OLD_BRANCHES = String.raw`\b(?:npm|pnpm|yarn|bun)\b[^;&|\n]*\b(?:uninstall|remove|rm|r|un|unlink)\s[^;&|\n]*\bpalizade\b|\b(?:rm|rmdir|mv|cp|sed|perl|python3?|node|ruby|truncate|tee|dd|shred|unlink|ln|chmod|chown|chattr|touch|install|del|erase|remove-item|move-item|set-content|out-file|clear-content)\b[^;&|\n]*(?:\.palizade\b|palizade\.(?:ya?ml|allow\.ya?ml|lock)\b|\.claude[\\/]settings(?:\.local)?\.json|\.claude\.json|\.mcp\.json|\.cursor[\\/](?:hooks|mcp)\.json|\.codex[\\/](?:config\.toml|hooks\.json)|\.gemini[\\/]settings\.json|claude_desktop_config\.json)`;

describe("self protection rule", () => {
  const current = new RegExp(selfRule("default"), "iu");
  const old = new RegExp(OLD_BRANCHES, "iu");
  const cleanStage = fc.constantFrom("git status", "git diff", "cat .claude/settings.json", "pnpm test", "grep -rn rm .",
    "docker build --rm -t app .", "mv src/a.ts .", "tar -czf out.tgz .", "palizade status", 'rg -F "a; rm .palizade" .');
  const cleanStages = fc.array(cleanStage, { maxLength: 7 });
  const separator = fc.constantFrom(" && ", " | ", "; ", "\n");
  const protectedStage = fc.oneof(
    fc.tuple(
      fc.constantFrom("rm -rf", "rmdir", "mv", "cp", "sed -i", "perl", "python3", "node", "ruby", "truncate", "tee",
        "dd", "shred", "unlink", "ln", "chmod", "chown", "chattr", "touch", "install", "del", "erase", "Remove-Item",
        "Move-Item", "Set-Content", "Out-File", "Clear-Content"),
      fc.constantFrom(".palizade/state", "palizade.yaml", "palizade.allow.yaml", "palizade.lock", ".claude/settings.json",
        ".claude/settings.local.json", ".claude.json", ".mcp.json", ".cursor/hooks.json", ".codex/config.toml",
        ".gemini/settings.json", "claude_desktop_config.json")
    ).map(([verb, path]) => `${verb} ${path}`),
    fc.tuple(
      fc.constantFrom("npm", "pnpm", "yarn", "bun"),
      fc.constantFrom("uninstall", "remove", "rm", "r", "un", "unlink")
    ).map(([pm, verb]) => `${pm} ${verb} palizade`)
  );

  it("is the same rule across all five presets", () => {
    expect(selfRule("strict")).toBe(selfRule("default"));
    expect(selfRule("coding-agent")).toBe(selfRule("default"));
    expect(selfRule("egress")).toBe(selfRule("default"));
    expect(selfRule("interactive")).toBe(selfRule("default"));
  });

  it("preserves the first version's protected stages and allows ordinary stages", () => {
    fc.assert(fc.property(cleanStages, cleanStages, separator, protectedStage, fc.constantFrom("", "sudo ", "A=1 env ", "cmd /c "),
      (before, after, joiner, protectedCommand, wrapper) => {
        expect(current.test([...before, ...after].join(joiner))).toBe(false);
        expect(old.test(protectedCommand)).toBe(true);
        expect(current.test([...before, wrapper + protectedCommand, ...after].join(joiner))).toBe(true);
      }), { numRuns: 2000 });
  });

  it("recognizes generated protected stages inside each shell wrapper", () => {
    const wrappers = [
      'bash -c "%s"', "sh -c '%s'", 'zsh -c "%s"', 'powershell -Command "%s"', "pwsh -NoProfile -Command %s",
      "& { %s }", "1 | % { %s }", "if ($true) { %s }", "{ %s; }",
      "if true; then %s; fi", "if false; then echo hi; else %s; fi", "for p in x; do %s; done",
      'iex "%s"', 'Invoke-Expression "%s"', "xargs %s", "timeout 5 %s", "nice -n 5 %s",
      "env -i %s", "sudo -u me %s", "doas -u me %s", "busybox %s", 'cmd /c "echo hi & %s"'
    ];
    fc.assert(fc.property(protectedStage, (command) => {
      for (const wrapper of wrappers) {
        const wrapped = wrapper.replace("%s", command);
        expect(current.test(wrapped), wrapped).toBe(true);
      }
    }), { numRuns: 200 });
  });

  it("bounds the regex alone on the reviewed worst cases", () => {
    for (const command of ["(".repeat(16_384), "\x60".repeat(16_384), "a(".repeat(8192), "a;".repeat(50_000), 'node -e "' + "a;".repeat(50_000) + '"']) {
      const start = performance.now();
      current.test(command);
      expect(performance.now() - start).toBeLessThan(1000);
    }
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
