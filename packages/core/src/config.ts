import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import YAML from "yaml";
import { z } from "zod";

const trustSchema = z.enum(["trusted", "semi", "untrusted"]);
const toolClassSchema = z.enum(["source", "sink", "pure", "unknown"]);
const capabilitySchema = z.enum([
  "reads_untrusted_content",
  "reads_sensitive_data",
  "network_egress",
  "writes_local",
  "writes_remote",
  "deletes_data",
  "executes_code",
  "sends_message",
  "accesses_credentials",
  "invokes_model",
  "user_interaction"
]);

export const serverConfigSchema = z.object({
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env: z.record(z.string(), z.string()).default({}),
  trust: trustSchema.default("untrusted"),
  toolClasses: z.record(z.string(), toolClassSchema).default({}),
  toolCapabilities: z.record(z.string(), z.array(capabilitySchema)).default({}),
  shell: z.boolean().default(false),
  allowShell: z.boolean().default(false)
}).strict();

export const palisadeConfigSchema = z.object({
  stateDir: z.string().default(".palisade"),
  policy: z.string().default("policies/default.yaml"),
  lockfile: z.string().default("palisade.lock"),
  audit: z.object({
    jsonl: z.string().default(".palisade/audit.jsonl"),
    sqlite: z.string().default(".palisade/audit.sqlite"),
    captureRawPayloads: z.boolean().default(false)
  }).default({ jsonl: ".palisade/audit.jsonl", sqlite: ".palisade/audit.sqlite", captureRawPayloads: false }),
  approvals: z.object({
    mode: z.enum(["terminal", "localhost", "static-allow", "static-deny"]).default("terminal"),
    timeoutMs: z.number().int().positive().default(30_000),
    default: z.enum(["allow", "deny"]).default("deny")
  }).default({ mode: "terminal", timeoutMs: 30_000, default: "deny" }),
  detectors: z.object({
    heuristic: z.boolean().default(true),
    onnxModelPath: z.string().optional(),
    promptGuard2: z.object({
      enabled: z.boolean().default(false),
      model: z.string().default("sinatras/Llama-Prompt-Guard-2-86M-ONNX"),
      cacheDir: z.string().optional(),
      device: z.string().default("cpu")
    }).default({ enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" })
  }).default({
    heuristic: true,
    promptGuard2: { enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" }
  }),
  transport: z.object({
    maxMessageBytes: z.number().int().min(1024).default(64 * 1024 * 1024),
    maxBufferedBytes: z.number().int().min(1024).default(64 * 1024 * 1024),
    allowBatches: z.boolean().default(false),
    allowContentLength: z.boolean().default(false)
  }).default({
    maxMessageBytes: 64 * 1024 * 1024,
    maxBufferedBytes: 64 * 1024 * 1024,
    allowBatches: false,
    allowContentLength: false
  }),
  taint: z.object({
    sqlite: z.string().default(".palisade/taint.sqlite"),
    keyPath: z.string().default(".palisade/taint.key"),
    scope: z.enum(["process", "profile", "external_run_id"]).default("profile"),
    profileId: z.string().default("default"),
    ttlMs: z.number().int().min(60_000).default(86_400_000),
    suspiciousScore: z.number().min(0).max(1).default(0.35),
    fuzzyHammingMax: z.number().int().min(0).max(64).default(7),
    temporal: z.object({
      enabled: z.boolean().default(true),
      turns: z.number().int().min(1).default(3),
      ttlMs: z.number().int().min(1000).default(300_000),
      detectorScoreGte: z.number().min(0).max(1).default(0.55)
    }).default({ enabled: true, turns: 3, ttlMs: 300_000, detectorScoreGte: 0.55 })
  }).default({
    sqlite: ".palisade/taint.sqlite",
    keyPath: ".palisade/taint.key",
    scope: "profile",
    profileId: "default",
    ttlMs: 86_400_000,
    suspiciousScore: 0.35,
    fuzzyHammingMax: 7,
    temporal: { enabled: true, turns: 3, ttlMs: 300_000, detectorScoreGte: 0.55 }
  }),
  servers: z.record(z.string(), serverConfigSchema).default({})
}).strict();

export type ServerConfig = z.infer<typeof serverConfigSchema>;
export type PalisadeConfig = z.infer<typeof palisadeConfigSchema>;

export async function loadConfig(path = "palisade.yaml", cwd = process.cwd()): Promise<PalisadeConfig> {
  const absolute = resolve(cwd, path);
  const raw = await readFile(absolute, "utf8");
  const parsed = palisadeConfigSchema.parse(YAML.parse(raw));
  return resolveConfigPaths(parsed, cwd);
}

export function parseConfig(raw: string, cwd = process.cwd()): PalisadeConfig {
  return resolveConfigPaths(palisadeConfigSchema.parse(YAML.parse(raw)), cwd);
}

export function resolveConfigPaths(config: PalisadeConfig, cwd = process.cwd()): PalisadeConfig {
  return {
    ...config,
    stateDir: resolve(cwd, config.stateDir),
    policy: resolve(cwd, config.policy),
    lockfile: resolve(cwd, config.lockfile),
    audit: {
      ...config.audit,
      jsonl: resolve(cwd, config.audit.jsonl),
      sqlite: resolve(cwd, config.audit.sqlite)
    },
    detectors: {
      ...config.detectors,
      onnxModelPath: config.detectors.onnxModelPath ? resolve(cwd, config.detectors.onnxModelPath) : undefined,
      promptGuard2: {
        ...config.detectors.promptGuard2,
        cacheDir: config.detectors.promptGuard2.cacheDir ? resolve(cwd, config.detectors.promptGuard2.cacheDir) : undefined
      }
    },
    taint: {
      ...config.taint,
      sqlite: resolve(cwd, config.taint.sqlite),
      keyPath: resolve(cwd, config.taint.keyPath)
    },
    servers: Object.fromEntries(Object.entries(config.servers).map(([name, server]) => [
      name,
      {
        ...server,
        cwd: server.cwd ? resolve(cwd, server.cwd) : cwd
      }
    ]))
  };
}
