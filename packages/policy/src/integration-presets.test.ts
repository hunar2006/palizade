import { expect, it } from "vitest";
import { evaluatePolicy } from "./evaluator.js";
import { loadPolicyFile } from "./loader.js";
import type { PolicyContext } from "./types.js";

it.each(["default", "interactive", "strict", "egress", "coding-agent"])("%s asks only for relevant shell stages and bounds self-protection work", async (preset) => {
  const policy = await loadPolicyFile(`policies/${preset}.yaml`);
  const evaluate = (command: string) => evaluatePolicy(policy, {
    direction: "request", method: "tools/call", tool_class: "sink",
    capabilities: ["executes_code", "network_egress", "writes_local"],
    argument_roles: ["shell_command"], argument_text: command
  });
  const rule = "approve-palizade-self-change";
  for (const command of [
    "grep -rn rm .", 'rg -n "del" .', "docker build --rm -t app .", "tar -czf out.tgz .", "mv src/a.ts .",
    'grep -F "x; rm -rf .claude" .', "grep -F 'npm uninstall palizade' .", "grep git clean .",
    "rm -r .unrelated*", "rg -n .cl* .", "palizade status; git status",
    'git commit -m "mention rm .claude in the notes"', 'echo "rm -rf .claude"'
  ]) {
    expect.soft(evaluate(command).matchedRuleId, command).not.toBe(rule);
  }
  for (const command of [
    "cmd /c rd /s /q .claude", 'cmd /c "rd /s /q .claude"', "rm -r .\\.cl*",
    '"C:/tools(x64)/rm.exe" -rf .claude', '"C:/tools(x64)/palizade.cmd" uninstall',
    '"C:/tools/palizade(x64)/dist/index.cjs" uninstall',
    'bash -c "rm -rf .claude"', "sh -c 'rm -rf .palizade'", 'zsh -c "rm -rf .claude"',
    'powershell -Command "Remove-Item -Recurse .claude"', "pwsh -NoProfile -Command Remove-Item -Recurse .claude",
    'powershell -Command "npm uninstall -g palizade"',
    "& { Remove-Item -Recurse .claude }", "1 | % { Remove-Item -Recurse .claude }",
    "function clean { rm -rf .claude; }",
    "if ($true) { Remove-Item -Recurse .claude }", "{ rm -rf .claude; }",
    "if true; then rm -rf .claude; else mv .palizade backup; fi", "for p in x; do rm -rf .claude; done",
    'iex "rm -r .claude"', 'Invoke-Expression "rm -r .claude"', "xargs rm -rf <<< .claude",
    "timeout 5 rm -rf .claude", "nice -n 5 rm -rf .claude", "env -i rm -rf .claude", "sudo -u me rm -rf .claude",
    "doas -u me rm -rf .claude", "busybox rm -rf .claude", 'cmd /c "echo hi & del /q .claude\\settings.json"',
    "echo ready && rm -r .palizade*", "echo ready | Move-Item .palizade* backup",
    "git checkout -- .", "git restore .", "git clean -fdx", "robocopy empty . /MIR", "tar -xf x.tar -C ."
  ]) {
    expect.soft(evaluate(command), command).toMatchObject({ action: "require_approval", matchedRuleId: rule });
  }
  const oversized = "a;".repeat(50_000);
  const start = performance.now();
  const decision = evaluate(oversized);
  expect.soft(performance.now() - start).toBeLessThan(500);
  expect.soft(decision).toMatchObject({ action: "require_approval", matchedRuleId: rule });
});

const sink: PolicyContext = { direction: "request", method: "tools/call", tool_class: "sink", capabilities: ["network_egress", "sends_message"], destination_allowed: true, destination_allowlist_configured: true };

it.each(["default", "interactive", "strict", "egress", "coding-agent"])("%s handles copied local shell commands", async (preset) => {
  const policy = await loadPolicyFile("policies/" + preset + ".yaml");
  const local = {
    ...sink, capabilities: ["executes_code", "network_egress", "writes_local"] as PolicyContext["capabilities"],
    taint: true, tainted_local_command: true, argument_roles: ["shell_command"], tainted_argument_roles: ["shell_command"]
  };
  expect(evaluatePolicy(policy, local)).toMatchObject(
    preset === "coding-agent"
      ? { action: "block", matchedRuleId: "block-tainted-shell" }
      : preset === "strict"
        ? { action: "block", matchedRuleId: "block-tainted-sink" }
        : { action: "require_approval", matchedRuleId: "approve-tainted-local-command" }
  );
  expect(evaluatePolicy(policy, { ...local, tainted_destination: true })).toMatchObject(
    preset === "coding-agent"
      ? { action: "block", matchedRuleId: "block-tainted-shell" }
      : { action: "block", matchedRuleId: "block-tainted-destination" }
  );
  expect(evaluatePolicy(policy, { ...local, tainted_argument_roles: ["url"], tainted_destination: true })).toMatchObject({
    action: "block", matchedRuleId: "block-tainted-destination"
  });
});

it.each(["default", "interactive", "strict", "egress", "coding-agent"])("%s blocks a tainted query before generic approval/redaction", async (preset) => {
  const policy = await loadPolicyFile(`policies/${preset}.yaml`);
  expect(evaluatePolicy(policy, { ...sink, taint: true, pii_detected: true, tainted_argument_roles: ["http_query"] }).action).toBe("block");
});
it("blocks strict suspicious output before sanitization and split egress before PII redaction", async () => {
  expect(evaluatePolicy(await loadPolicyFile("policies/strict.yaml"), { direction: "response", method: "tools/call", detector_score: 0.85 }).action).toBe("block");
  expect(evaluatePolicy(await loadPolicyFile("policies/egress.yaml"), { ...sink, split_match: true, pii_detected: true }).matchedRuleId).toBe("block-split-match");
});
it("egress exceptions cannot bypass critical-path or quarantine approval", async () => {
  const policy = await loadPolicyFile("policies/egress.yaml");
  const fileSink = { ...sink, capabilities: ["writes_local", "network_egress"] } as PolicyContext;
  expect(evaluatePolicy(policy, { ...fileSink, pii_detected: true, critical_path: true }).matchedRuleId).toBe("approve-critical-path");
  expect(evaluatePolicy(policy, { ...sink, pii_detected: true, session_quarantined: true }).matchedRuleId).toBe("approve-quarantined-sink");
  expect(evaluatePolicy(policy, { ...sink, pii_detected: true }).action).toBe("redact_secrets");
  expect(evaluatePolicy(policy, { ...sink, taint: true, argument_roles: ["url"] }).action).toBe("allow");
  expect(evaluatePolicy(policy, { ...sink, taint: true }).action).toBe("block");
});
it("research gates permitted output during quarantine and passes normal output", async () => {
  const policy = await loadPolicyFile("policies/research-readonly.yaml");
  const output = { ...sink, capabilities: ["writes_local"], output_path_allowed: true } as PolicyContext;
  expect(evaluatePolicy(policy, { ...output, session_quarantined: true }).action).toBe("require_approval");
  expect(evaluatePolicy(policy, output).action).toBe("allow");
});
it.each(["default", "interactive", "strict"])("%s asks before deleting data once the session has seen untrusted content", async (preset) => {
  const policy = await loadPolicyFile(`policies/${preset}.yaml`);
  const deleteCall: PolicyContext = { direction: "request", method: "tools/call", tool_class: "sink", capabilities: ["deletes_data"], trust: "trusted" };
  expect(evaluatePolicy(policy, { ...deleteCall, session_untrusted: true }).matchedRuleId).toBe("approve-delete-after-untrusted");
  expect(evaluatePolicy(policy, deleteCall).matchedRuleId).not.toBe("approve-delete-after-untrusted");
});
