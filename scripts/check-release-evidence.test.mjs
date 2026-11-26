import assert from "node:assert/strict";
import { test } from "node:test";
import { checkReleaseEvidence } from "./check-release-evidence.mjs";

const commit = "a".repeat(40);
const version = "0.4.0";
const live = { mode: "live", clientVersion: "test-version", platform: "test-platform", model: "test-model",
  cleanTasks: 3, completedTasks: 3, falseBlocks: 0, approvals: 1, deniedTests: 1, confirmedDenials: 1 };
const clients = Object.fromEntries(["claude-desktop", "claude-code", "cursor", "codex", "gemini"].map((client) => [client, live]));

test("matches live evidence to the specific release candidate", () => {
  const evidence = { commit, version, clients };
  assert.doesNotThrow(() => checkReleaseEvidence(evidence, commit, version));
  assert.throws(() => checkReleaseEvidence(evidence, "b".repeat(40), version), /commit and package version/);
  assert.throws(() => checkReleaseEvidence(evidence, commit, "0.5.0"), /commit and package version/);
});

test("rejects missing, scripted, or failed live checks", () => {
  for (const codex of [undefined, { ...live, mode: "scripted" }, { ...live, confirmedDenials: 0 }, { ...live, falseBlocks: 1 }]) {
    assert.throws(() => checkReleaseEvidence({ commit, version, clients: { ...clients, codex } }, commit, version), /codex/);
  }
});
