import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Ajv } from "ajv";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import { formatSarif, type ScanResult } from "../src/scan.js";

// The SARIF 2.1.0 schema as published by SchemaStore (https://json.schemastore.org/sarif-2.1.0.json),
// a draft-07 copy of the OASIS schema that code scanning services validate against.
const schema = JSON.parse(readFileSync(resolve("packages/cli/test/fixtures/sarif-schema-2.1.0.json"), "utf8")) as object;
const ajv = new Ajv({ strict: false, allErrors: true });
(addFormats as unknown as (ajv: Ajv) => void)(ajv);
const validate = ajv.compile(schema);
const valid = (text: string) => {
  const ok = validate(JSON.parse(text));
  return ok ? [] : (validate.errors ?? []).map((error) => `${error.instancePath} ${error.message}`);
};

describe("scan --format sarif", () => {
  it("writes valid SARIF 2.1.0 with one rule per check and relative paths in the project", () => {
    const cwd = resolve(tmpdir(), "project");
    const result: ScanResult = {
      files: [],
      findings: [
        { severity: "high", source: join(cwd, ".mcp.json"), server: "github", check: "plaintext-secret", message: "GITHUB_TOKEN is stored in plain text.", fix: "Use ${GITHUB_TOKEN}." },
        { severity: "medium", source: "claude-code project", path: join(cwd, ".mcp.json"), server: "fetch", check: "unprotected", message: "Not wrapped by Palizade." },
        { severity: "low", source: resolve(tmpdir(), "elsewhere", "mcp.json"), server: "x", check: "unpinned-package", message: "Unpinned." },
        { severity: "info", source: join(cwd, "my config", "palizade.yaml"), server: "y", check: "unprotected", message: "Info." }
      ]
    };
    const text = formatSarif(result, { version: "9.9.9", cwd });
    expect(valid(text)).toEqual([]);
    const run = JSON.parse(text).runs[0];
    expect(run.tool.driver).toMatchObject({ name: "Palizade", version: "9.9.9" });
    expect(run.tool.driver.rules.map((rule: { id: string }) => rule.id)).toEqual(["plaintext-secret", "unpinned-package", "unprotected"]);
    expect(run.results.map((entry: { level: string }) => entry.level)).toEqual(["error", "warning", "note", "note"]);
    expect(run.results[0].locations[0].physicalLocation.artifactLocation).toEqual({ uri: ".mcp.json", uriBaseId: "%SRCROOT%" });
    expect(run.results[1].locations[0].physicalLocation.artifactLocation).toEqual({ uri: ".mcp.json", uriBaseId: "%SRCROOT%" });
    expect(run.results[3].locations[0].physicalLocation.artifactLocation.uri).toBe("my%20config/palizade.yaml");
    expect(run.results[0].message.text).toBe("github: GITHUB_TOKEN is stored in plain text. Fix: Use ${GITHUB_TOKEN}.");
    expect(run.results[2].locations[0].physicalLocation.artifactLocation.uri).toMatch(/^file:\/\//u);
    expect(run.results[0].ruleId).toBe(run.tool.driver.rules[run.results[0].ruleIndex].id);
    expect(valid(formatSarif({ files: [], findings: [] }, { version: "1.0.0", cwd }))).toEqual([]);
  });

  it("prints SARIF from the CLI and keeps the --fail-on exit code", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-sarif-"));
    try {
      await writeFile(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { fetch: { command: "npx", args: ["-y", "some-mcp-server"] } } }));
      const run = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "scan", "--project-only", "--format", "sarif", "--fail-on", "low"], { cwd: dir, encoding: "utf8", env: { ...process.env, HOME: dir, USERPROFILE: dir } });
      expect(valid(run.stdout)).toEqual([]);
      const results = JSON.parse(run.stdout).runs[0].results as Array<{ ruleId: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((entry) => entry.ruleId === "unprotected" && entry.locations[0]!.physicalLocation.artifactLocation.uri === ".mcp.json")).toBe(true);
      expect(run.status).toBe(1);
      const bad = spawnSync(process.execPath, [resolve("packages/cli/dist/index.cjs"), "scan", "--project-only", "--format", "xml"], { cwd: dir, encoding: "utf8" });
      expect(bad.status).not.toBe(0);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
