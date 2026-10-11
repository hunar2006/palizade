import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import {
  escapeNonPrinting,
  findDangerousDefaults,
  findHiddenUnicode,
  stripHiddenUnicode,
  type DangerousDefaultFinding,
  type DetectionResult,
  type HiddenUnicodeFinding
} from "@palizade/detectors";
import { applyTextTransforms } from "./text.js";

export const DEFAULT_BUILTIN_TOOL_NAMES = ["read_file", "write_file", "bash", "fetch"];

export interface MetadataGuardConfig {
  shadowing: boolean;
  builtinNames: string[];
  dangerousDefaults: string[];
  maxScanBytes: number;
}

export const DEFAULT_METADATA_GUARD_CONFIG: MetadataGuardConfig = {
  shadowing: true,
  builtinNames: DEFAULT_BUILTIN_TOOL_NAMES,
  dangerousDefaults: [],
  maxScanBytes: 256 * 1024
};

export interface RegisteredTool {
  server: string;
  tool: string;
}

export interface ToolRegistry {
  replaceServerTools(server: string, tools: string[]): void;
  listTools(): RegisteredTool[];
  close?(): void;
}

export class InMemoryToolRegistry implements ToolRegistry {
  private readonly servers = new Map<string, string[]>();

  replaceServerTools(server: string, tools: string[]): void {
    this.servers.set(server, [...new Set(tools)]);
  }

  listTools(): RegisteredTool[] {
    return [...this.servers.entries()].flatMap(([server, tools]) => tools.map((tool) => ({ server, tool })));
  }
}

type SqliteDatabase = {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...args: unknown[]): void;
    all(...args: unknown[]): unknown[];
  };
  close(): void;
};

/** Tool names of every wrapped server, shared by all Palizade processes using the same state directory. */
export class SqliteToolRegistry implements ToolRegistry {
  private readonly db: SqliteDatabase;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    const load = createRequire(resolve(process.cwd(), ".palizade", "registry-sqlite.cjs"));
    const sqlite = load("node:sqlite") as { DatabaseSync: new (path: string) => SqliteDatabase };
    this.db = new sqlite.DatabaseSync(path);
    this.db.exec(`
      pragma busy_timeout = 2000;
      create table if not exists tool_registry (
        server text not null,
        tool text not null,
        updated_at text not null,
        primary key (server, tool)
      );
    `);
  }

  replaceServerTools(server: string, tools: string[]): void {
    const now = new Date().toISOString();
    this.db.exec("begin immediate");
    try {
      this.db.prepare("delete from tool_registry where server = ?").run(server);
      const insert = this.db.prepare("insert or replace into tool_registry (server, tool, updated_at) values (?, ?, ?)");
      for (const tool of new Set(tools)) {
        insert.run(server, tool, now);
      }
      this.db.exec("commit");
    } catch (error) {
      this.db.exec("rollback");
      throw error;
    }
  }

  listTools(): RegisteredTool[] {
    return this.db.prepare("select server, tool from tool_registry").all() as RegisteredTool[];
  }

  close(): void {
    this.db.close();
  }
}

export interface MetadataItem {
  name: string;
  value: unknown;
}

export interface MetadataItemReview {
  name: string;
  hiddenUnicode: HiddenUnicodeFinding;
  hiddenPayload?: string | undefined;
  shadows: RegisteredTool[];
  collidesWith: string[];
  builtinName: boolean;
  dangerousDefaults: DangerousDefaultFinding[];
  detection: DetectionResult;
  flagged: boolean;
}

export interface MetadataReview {
  items: MetadataItemReview[];
  labels: string[];
  hiddenUnicode: boolean;
  shadowing: boolean;
  collision: boolean;
}

export interface MetadataReviewOptions {
  serverName: string;
  configuredServers: string[];
  registry: ToolRegistry;
  config: MetadataGuardConfig;
  /** true for tools/list: registers names and checks collisions. */
  tools: boolean;
  detect: (text: string, itemName: string) => Promise<DetectionResult> | DetectionResult;
}

export async function reviewMetadata(items: MetadataItem[], options: MetadataReviewOptions): Promise<MetadataReview> {
  const configured = new Set(options.configuredServers);
  if (options.tools) {
    options.registry.replaceServerTools(options.serverName, items.map((item) => item.name));
  }
  const others = options.registry.listTools()
    .filter((entry) => entry.server !== options.serverName && (configured.size === 0 || configured.has(entry.server)));
  const ownNames = new Set(items.map((item) => item.name));
  const builtins = new Set(options.config.builtinNames.map((name) => name.toLowerCase()));

  const reviews: MetadataItemReview[] = [];
  for (const item of items) {
    const raw = collectMetadataText(item.value, options.config.maxScanBytes);
    const hiddenUnicode = findHiddenUnicode(raw);
    const visible = stripHiddenUnicode(raw);
    const hiddenPayload = decodeTagPayload(raw);
    const shadows = options.config.shadowing
      ? others.filter((entry) => !ownNames.has(entry.tool) && mentionsTool(visible, entry))
      : [];
    // shortcut: collisions are checked when this server answers tools/list, so a second server that registers the same name later is only caught on its own list, re-check on tools/call once list_changed handling (M5) refreshes the registry.
    const collidesWith = options.tools
      ? [...new Set(others.filter((entry) => entry.tool === item.name).map((entry) => entry.server))]
      : [];
    const builtinName = options.tools && builtins.has(item.name.toLowerCase());
    const dangerousDefaults = findDangerousDefaults(item.value, options.config.dangerousDefaults);

    const labels: string[] = [];
    let score = 0;
    if (hiddenUnicode.count > 0) {
      labels.push("hidden_unicode");
      score = Math.max(score, 0.4);
    }
    if (shadows.length > 0) {
      labels.push("tool_shadowing");
      score = Math.max(score, 0.5);
    }
    if (collidesWith.length > 0) labels.push("tool_name_collision");
    if (builtinName) labels.push("builtin_tool_name");
    if (dangerousDefaults.length > 0) {
      labels.push("dangerous_default");
      score = Math.max(score, 0.4);
    }
    const detections: DetectionResult[] = [{ score, labels, detector: "metadata-guard" }];
    if (hiddenPayload) {
      const payloadDetection = await options.detect(hiddenPayload, item.name);
      detections.push({ ...payloadDetection, labels: payloadDetection.labels.map((label) => `hidden:${label}`), spans: [] });
    }
    const detection: DetectionResult = {
      score: Math.max(...detections.map((entry) => entry.score)),
      labels: [...new Set(detections.flatMap((entry) => entry.labels))],
      detector: "metadata-guard",
      metadata: {
        hiddenUnicode: hiddenUnicode.count > 0 ? hiddenUnicode : undefined,
        shadows: shadows.length > 0 ? shadows : undefined,
        collidesWith: collidesWith.length > 0 ? collidesWith : undefined,
        dangerousDefaults: dangerousDefaults.length > 0 ? dangerousDefaults : undefined,
        hiddenPayload: hiddenPayload ? escapeNonPrinting(hiddenPayload.slice(0, 200)) : undefined
      }
    };
    reviews.push({
      name: item.name,
      hiddenUnicode,
      hiddenPayload,
      shadows,
      collidesWith,
      builtinName,
      dangerousDefaults,
      detection,
      flagged: hiddenUnicode.count > 0 || shadows.length > 0 || collidesWith.length > 0 || dangerousDefaults.length > 0
    });
  }

  return {
    items: reviews,
    labels: [...new Set(reviews.flatMap((review) => review.detection.labels))],
    hiddenUnicode: reviews.some((review) => review.hiddenUnicode.count > 0),
    shadowing: reviews.some((review) => review.shadows.length > 0),
    collision: reviews.some((review) => review.collidesWith.length > 0)
  };
}

/** Removes hidden characters from every string value; keeps valid emoji sequences. */
export function stripHiddenUnicodeDeep<T>(value: T): T {
  if (typeof value === "string") {
    return stripHiddenUnicode(value) as T;
  }
  // shortcut: object keys are scanned but not rewritten (renaming schema properties would break calls), sanitize keys once a schema-aware rewriter exists.
  return applyTextTransforms(value, (text) => stripHiddenUnicode(text)) as T;
}

/** Unicode TAG characters U+E0020..U+E007E mirror printable ASCII; decode them so hidden instructions are scanned. */
export function decodeTagPayload(text: string): string | undefined {
  let decoded = "";
  for (const char of text) {
    const cp = char.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) {
      decoded += String.fromCharCode(cp - 0xe0000);
    }
  }
  return decoded.trim().length >= 4 ? decoded : undefined;
}

function collectMetadataText(value: unknown, maxBytes: number): string {
  const parts: string[] = [];
  let size = 0;
  const visit = (node: unknown, depth: number): void => {
    if (size >= maxBytes || depth > 32) return;
    if (typeof node === "string") {
      parts.push(node);
      size += node.length;
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1);
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
        parts.push(key);
        size += key.length;
        visit(child, depth + 1);
      }
    }
  };
  visit(value, 0);
  return parts.join("\n").slice(0, maxBytes);
}

function mentionsTool(text: string, entry: RegisteredTool): boolean {
  const qualified = [`${entry.server}.${entry.tool}`, `${entry.server}/${entry.tool}`, `${entry.server}:${entry.tool}`, `${entry.server}__${entry.tool}`];
  const lowered = text.toLowerCase();
  if (qualified.some((name) => lowered.includes(name.toLowerCase()))) {
    return true;
  }
  if (!isDistinctiveToolName(entry.tool)) {
    return false;
  }
  const escaped = entry.tool.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])`, "u").test(text);
}

/** Plain words such as "search" or "fetch" appear in ordinary prose; only compound names count as exact mentions. */
function isDistinctiveToolName(name: string): boolean {
  return name.length >= 4 && (/[_\-.]/u.test(name) || /[a-z][A-Z]/u.test(name) || /\d/u.test(name));
}
