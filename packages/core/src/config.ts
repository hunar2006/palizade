import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import YAML from "yaml";
import { z } from "zod";

const trustSchema = z.enum(["trusted", "semi", "untrusted"]);
const toolClassSchema = z.enum(["source", "sink", "pure", "unknown"]);
const capabilitySchema = z.enum([
  "reads_untrusted_content",
  "reads_sensitive_data",
  "network_egress",
  "file_write",
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
  sensitive: z.boolean().default(false),
  sensitiveTools: z.record(z.string(), z.boolean()).default({}),
  sensitivePathPatterns: z.array(z.string()).default([]),
  shell: z.boolean().default(false),
  allowShell: z.boolean().default(false)
}).strict();

const secretDetectorConfigSchema = z.object({
  enabled: z.boolean().default(false),
  aws: z.boolean().default(true),
  generic: z.boolean().default(true),
  jwt: z.boolean().default(true),
  privateKey: z.boolean().default(true),
  googleApiKey: z.boolean().default(true),
  stripe: z.boolean().default(true),
  slack: z.boolean().default(true),
  github: z.boolean().default(true),
  openai: z.boolean().default(true)
}).default({
  enabled: false,
  aws: true,
  generic: true,
  jwt: true,
  privateKey: true,
  googleApiKey: true,
  stripe: true,
  slack: true,
  github: true,
  openai: true
});

const piiDetectorConfigSchema = z.object({
  enabled: z.boolean().default(false),
  email: z.boolean().default(true),
  ssn: z.boolean().default(true),
  creditCard: z.boolean().default(true),
  phone: z.boolean().default(true)
}).default({
  enabled: false,
  email: true,
  ssn: true,
  creditCard: true,
  phone: true
});

export const palizadeConfigSchema = z.object({
  stateDir: z.string().default(".palizade"),
  policy: z.string().default("policies/default.yaml"),
  lockfile: z.string().default("palizade.lock"),
  audit: z.object({
    jsonl: z.string().default(".palizade/audit.jsonl"),
    sqlite: z.string().default(".palizade/audit.sqlite"),
    captureRawPayloads: z.boolean().default(false),
    errorVerbosity: z.boolean().default(true)
  }).default({ jsonl: ".palizade/audit.jsonl", sqlite: ".palizade/audit.sqlite", captureRawPayloads: false, errorVerbosity: true }),
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
    }).default({ enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" }),
    secrets: secretDetectorConfigSchema,
    pii: piiDetectorConfigSchema
  }).default({
    heuristic: true,
    promptGuard2: { enabled: false, model: "sinatras/Llama-Prompt-Guard-2-86M-ONNX", device: "cpu" },
    secrets: { enabled: false, aws: true, generic: true, jwt: true, privateKey: true, googleApiKey: true, stripe: true, slack: true, github: true, openai: true },
    pii: { enabled: false, email: true, ssn: true, creditCard: true, phone: true }
  }),
  egress: z.object({
    allowlist: z.object({
      hosts: z.array(z.string()).default([]),
      emails: z.array(z.string()).default([])
    }).default({ hosts: [], emails: [] })
  }).default({
    allowlist: { hosts: [], emails: [] }
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
    sqlite: z.string().default(".palizade/taint.sqlite"),
    keyPath: z.string().default(".palizade/taint.key"),
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
    sqlite: ".palizade/taint.sqlite",
    keyPath: ".palizade/taint.key",
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
export type PalizadeConfig = z.infer<typeof palizadeConfigSchema>;

export async function loadConfig(path = "palizade.yaml", cwd = process.cwd()): Promise<PalizadeConfig> {
  const absolute = resolve(cwd, path);
  const raw = await readFile(absolute, "utf8");
  const parsed = palizadeConfigSchema.parse(YAML.parse(raw));
  return resolveConfigPaths(parsed, dirname(absolute));
}

export function parseConfig(raw: string, baseDir = process.cwd()): PalizadeConfig {
  return resolveConfigPaths(palizadeConfigSchema.parse(YAML.parse(raw)), baseDir);
}

export function resolveConfigPaths(config: PalizadeConfig, baseDir = process.cwd()): PalizadeConfig {
  return {
    ...config,
    stateDir: resolvePath(baseDir, config.stateDir),
    policy: resolvePath(baseDir, config.policy),
    lockfile: resolvePath(baseDir, config.lockfile),
    audit: {
      ...config.audit,
      jsonl: resolvePath(baseDir, config.audit.jsonl),
      sqlite: resolvePath(baseDir, config.audit.sqlite)
    },
    detectors: {
      ...config.detectors,
      onnxModelPath: config.detectors.onnxModelPath ? resolvePath(baseDir, config.detectors.onnxModelPath) : undefined,
      promptGuard2: {
        ...config.detectors.promptGuard2,
        cacheDir: config.detectors.promptGuard2.cacheDir ? resolvePath(baseDir, config.detectors.promptGuard2.cacheDir) : undefined
      }
    },
    taint: {
      ...config.taint,
      sqlite: resolvePath(baseDir, config.taint.sqlite),
      keyPath: resolvePath(baseDir, config.taint.keyPath)
    },
    servers: Object.fromEntries(Object.entries(config.servers).map(([name, server]) => [
      name,
      {
        ...server,
        cwd: server.cwd ? resolvePath(baseDir, server.cwd) : baseDir
      }
    ]))
  };
}

function resolvePath(baseDir: string, path: string): string {
  return isAbsolute(path) ? path : resolve(baseDir, path);
}
