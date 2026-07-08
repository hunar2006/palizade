#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { SensitiveDataDetector, isSecretLabel } from "../packages/detectors/dist/index.js";

const adversarial = JSON.parse(await readFile(new URL("./detector-adversarial/adversarial.json", import.meta.url), "utf8"));
const benign = JSON.parse(await readFile(new URL("./detector-adversarial/benign.json", import.meta.url), "utf8"));

const detector = new SensitiveDataDetector({
  secrets: { enabled: true },
  pii: { enabled: false }
});

const adversarialResults = adversarial.map((testCase) => scoreCase(testCase));
const benignResults = benign.map((testCase) => scoreCase(testCase));
const detectedAdversarial = adversarialResults.filter((row) => row.detected);
const falsePositives = benignResults.filter((row) => row.detected);

console.log("Palizade sensitive-data detector adversarial report");
console.log("Detector mode: SensitiveDataDetector secrets enabled, PII disabled for this secret-focused corpus.");
console.log("");
console.log("| Corpus | Detected | Total | Rate |");
console.log("| --- | ---: | ---: | ---: |");
console.log(`| adversarial secrets | ${detectedAdversarial.length} | ${adversarialResults.length} | ${formatPercent(detectedAdversarial.length, adversarialResults.length)} |`);
console.log(`| benign false positives | ${falsePositives.length} | ${benignResults.length} | ${formatPercent(falsePositives.length, benignResults.length)} |`);

console.log("");
console.log("| Obfuscation | Detected | Total | Rate |");
console.log("| --- | ---: | ---: | ---: |");
for (const [obfuscation, rows] of groupedBy(adversarialResults, (row) => row.obfuscation).entries()) {
  const detected = rows.filter((row) => row.detected).length;
  console.log(`| ${obfuscation} | ${detected} | ${rows.length} | ${formatPercent(detected, rows.length)} |`);
}

console.log("");
console.log("| Label | Count |");
console.log("| --- | ---: |");
for (const [label, count] of labelCounts([...adversarialResults, ...benignResults]).entries()) {
  console.log(`| ${label} | ${count} |`);
}

const missedExpected = adversarialResults.filter((row) => row.expected_detected && !row.detected);
const unexpectedDetected = adversarialResults.filter((row) => !row.expected_detected && row.detected);

console.log("");
console.log(`Missed expected detections: ${missedExpected.map((row) => row.id).join(", ") || "none"}`);
console.log(`Detected known-limit cases: ${unexpectedDetected.map((row) => row.id).join(", ") || "none"}`);
console.log(`Benign false positives: ${falsePositives.map((row) => row.id).join(", ") || "none"}`);

if (benignResults.length > 0 && falsePositives.length / benignResults.length > 0.05) {
  console.error("Benign false-positive rate exceeded 5%.");
  process.exitCode = 1;
}

function scoreCase(testCase) {
  const result = detector.detect(testCase.text, { surface: "argument", trust: "semi" });
  return {
    ...testCase,
    score: result.score,
    labels: result.labels,
    detected: result.labels.some(isSecretLabel)
  };
}

function groupedBy(rows, keyFn) {
  const groups = new Map();
  for (const row of rows) {
    const key = keyFn(row);
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return new Map([...groups.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function labelCounts(rows) {
  const counts = new Map();
  for (const row of rows) {
    for (const label of row.labels) {
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
  }
  return new Map([...counts.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function formatPercent(numerator, denominator) {
  if (denominator === 0) {
    return "0.0%";
  }
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}
