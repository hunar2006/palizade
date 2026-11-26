import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const requiredClients = ["claude-desktop", "claude-code", "cursor", "codex", "gemini"];

export function checkReleaseEvidence(evidence, commit, version) {
  if (!/^[a-f0-9]{40}$/u.test(commit) || evidence?.commit !== commit || evidence.version !== version) {
    throw new Error("Client verification must match the tagged commit and package version.");
  }
  for (const client of requiredClients) {
    const result = evidence.clients?.[client];
    if (result?.mode !== "live" || !nonempty(result.clientVersion) || !nonempty(result.platform) || !nonempty(result.model)) {
      throw new Error(`Missing live verification details for ${client}.`);
    }
    const { cleanTasks, completedTasks, falseBlocks, approvals, deniedTests, confirmedDenials } = result;
    const counts = [cleanTasks, completedTasks, falseBlocks, approvals, deniedTests, confirmedDenials];
    if (!counts.every((count) => Number.isSafeInteger(count) && count >= 0) ||
        cleanTasks === 0 || cleanTasks !== completedTasks || falseBlocks !== 0 ||
        deniedTests === 0 || deniedTests !== confirmedDenials) {
      throw new Error(`Live allow/deny verification did not pass for ${client}.`);
    }
  }
}

function nonempty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const evidence = JSON.parse(readFileSync(0, "utf8"));
    checkReleaseEvidence(evidence, process.argv[2], process.argv[3]);
    console.log("Live verification passed for all five clients.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
