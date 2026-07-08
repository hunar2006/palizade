import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("resolves config paths relative to the config file, not the caller cwd", async () => {
    const root = await mkdtemp(join(tmpdir(), "palizade-config-"));
    const configDir = join(root, "project");
    const otherCwd = join(root, "spawn-cwd");
    const configPath = join(configDir, "palizade.yaml");
    await mkdir(configDir, { recursive: true });
    await writeFile(configPath, relativeConfig(), "utf8");

    try {
      const config = await loadConfig(configPath, otherCwd);

      expect(config.stateDir).toBe(join(configDir, ".palizade"));
      expect(config.policy).toBe(join(configDir, "policies", "default.yaml"));
      expect(config.lockfile).toBe(join(configDir, "palizade.lock"));
      expect(config.audit.jsonl).toBe(join(configDir, ".palizade", "audit.jsonl"));
      expect(config.audit.sqlite).toBe(join(configDir, ".palizade", "audit.sqlite"));
      expect(config.taint.sqlite).toBe(join(configDir, ".palizade", "taint.sqlite"));
      expect(config.taint.keyPath).toBe(join(configDir, ".palizade", "taint.key"));
      expect(config.detectors.promptGuard2.cacheDir).toBe(join(configDir, ".palizade", "models"));
      expect(config.detectors.onnxModelPath).toBe(join(configDir, "models", "detector.onnx"));
      expect(config.detectors.secrets.enabled).toBe(false);
      expect(config.detectors.pii.enabled).toBe(false);
      expect(config.approvals.timeoutMs).toBe(120_000);
      expect(config.approvals.host).toBe("127.0.0.1");
      expect(config.approvals.port).toBe(32_145);
      expect(config.approvals.openBrowser).toBe(true);
      expect(config.egress.allowlist.hosts).toEqual([]);
      expect(config.egress.allowlist.emails).toEqual([]);
      expect(config.servers.filesystem?.cwd).toBe(join(configDir, "servers"));
      expect(config.servers.filesystem?.command).toBe("node");
      expect(config.servers.filesystem?.args).toEqual(["node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "."]);
      expect(config.servers.filesystem?.sensitive).toBe(false);
      expect(config.servers.filesystem?.sensitiveTools).toEqual({});
      expect(config.servers.filesystem?.sensitivePathPatterns).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("passes absolute config paths through unchanged", async () => {
    const root = await mkdtemp(join(tmpdir(), "palizade-config-"));
    const configDir = join(root, "project");
    const otherCwd = join(root, "spawn-cwd");
    const paths = {
      stateDir: join(root, "abs-state"),
      policy: join(root, "abs-policy.yaml"),
      lockfile: join(root, "abs.lock"),
      auditJsonl: join(root, "audit.jsonl"),
      auditSqlite: join(root, "audit.sqlite"),
      taintSqlite: join(root, "taint.sqlite"),
      taintKey: join(root, "taint.key"),
      promptGuardCache: join(root, "models"),
      onnxModelPath: join(root, "detector.onnx"),
      serverCwd: join(root, "server-cwd")
    };
    const configPath = join(configDir, "palizade.yaml");
    await mkdir(configDir, { recursive: true });
    await writeFile(configPath, absoluteConfig(paths), "utf8");

    try {
      const config = await loadConfig(configPath, otherCwd);

      expect(config.stateDir).toBe(paths.stateDir);
      expect(config.policy).toBe(paths.policy);
      expect(config.lockfile).toBe(paths.lockfile);
      expect(config.audit.jsonl).toBe(paths.auditJsonl);
      expect(config.audit.sqlite).toBe(paths.auditSqlite);
      expect(config.taint.sqlite).toBe(paths.taintSqlite);
      expect(config.taint.keyPath).toBe(paths.taintKey);
      expect(config.detectors.promptGuard2.cacheDir).toBe(paths.promptGuardCache);
      expect(config.detectors.onnxModelPath).toBe(paths.onnxModelPath);
      expect(config.servers.filesystem?.cwd).toBe(paths.serverCwd);
      expect(config.servers.filesystem?.args).toEqual(["relative-arg-kept"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function relativeConfig(): string {
  return `stateDir: .palizade
policy: policies/default.yaml
lockfile: palizade.lock
audit:
  jsonl: .palizade/audit.jsonl
  sqlite: .palizade/audit.sqlite
detectors:
  heuristic: true
  onnxModelPath: models/detector.onnx
  promptGuard2:
    enabled: true
    cacheDir: .palizade/models
taint:
  sqlite: .palizade/taint.sqlite
  keyPath: .palizade/taint.key
servers:
  filesystem:
    command: node
    args:
      - node_modules/@modelcontextprotocol/server-filesystem/dist/index.js
      - .
    cwd: servers
`;
}

interface AbsoluteConfigPaths {
  stateDir: string;
  policy: string;
  lockfile: string;
  auditJsonl: string;
  auditSqlite: string;
  taintSqlite: string;
  taintKey: string;
  promptGuardCache: string;
  onnxModelPath: string;
  serverCwd: string;
}

function absoluteConfig(paths: AbsoluteConfigPaths): string {
  return `stateDir: ${yamlPath(paths.stateDir)}
policy: ${yamlPath(paths.policy)}
lockfile: ${yamlPath(paths.lockfile)}
audit:
  jsonl: ${yamlPath(paths.auditJsonl)}
  sqlite: ${yamlPath(paths.auditSqlite)}
detectors:
  heuristic: true
  onnxModelPath: ${yamlPath(paths.onnxModelPath)}
  promptGuard2:
    enabled: true
    cacheDir: ${yamlPath(paths.promptGuardCache)}
taint:
  sqlite: ${yamlPath(paths.taintSqlite)}
  keyPath: ${yamlPath(paths.taintKey)}
servers:
  filesystem:
    command: node
    args:
      - relative-arg-kept
    cwd: ${yamlPath(paths.serverCwd)}
`;
}

function yamlPath(path: string): string {
  return JSON.stringify(resolve(path));
}
