import type { TrustLevel } from "@palisade/policy";

export type ContentOrigin =
  | "tool_metadata"
  | "tool_result"
  | "resource_metadata"
  | "resource_content"
  | "prompt_metadata"
  | "prompt_content"
  | "sampling_request"
  | "elicitation_request"
  | "notification";

export type ExtractedContentKind = "text" | "url" | "binary" | "structured" | "metadata";

export interface ExtractedContent {
  path: string;
  kind: ExtractedContentKind;
  text?: string | undefined;
  rawValue?: unknown;
  origin: ContentOrigin;
  sourceServer: string;
  sourceMethod: string;
  sourceToolOrResource?: string | undefined;
  mimeType?: string | undefined;
  trust: TrustLevel;
}

export interface ExtractionContext {
  origin: ContentOrigin;
  sourceServer: string;
  sourceMethod: string;
  sourceToolOrResource?: string | undefined;
  trust: TrustLevel;
}

const HUMAN_METADATA_KEYS = /(^|\.)(name|title|description|summary|instructions?|prompt|text|content|uri|url|mimeType|mime_type|label|message|argument|schema|annotations?)$/iu;
const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
const BASE64ISH_RE = /^[A-Za-z0-9+/]{80,}={0,2}$/u;

export function extractContent(value: unknown, ctx: ExtractionContext): ExtractedContent[] {
  const output: ExtractedContent[] = [];
  visit(value, "$", ctx, output);
  return dedupe(output);
}

export function contentText(contents: ExtractedContent[]): string {
  return contents
    .map((content) => content.text)
    .filter((text): text is string => Boolean(text?.trim()))
    .join("\n");
}

function visit(value: unknown, path: string, ctx: ExtractionContext, output: ExtractedContent[]): void {
  if (typeof value === "string") {
    emitString(value, path, ctx, output);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => visit(item, `${path}[${index}]`, ctx, output));
    return;
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const mimeType = typeof record.mimeType === "string" ? record.mimeType : typeof record.mime_type === "string" ? record.mime_type : undefined;
    const resourceName = firstString(record.name, record.uri, record.uriTemplate, record.title);
    const childCtx = resourceName ? { ...ctx, sourceToolOrResource: ctx.sourceToolOrResource ?? resourceName } : ctx;

    if (typeof record.blob === "string") {
      output.push({
        path: `${path}.blob`,
        kind: "binary",
        rawValue: "[binary omitted]",
        origin: ctx.origin,
        sourceServer: ctx.sourceServer,
        sourceMethod: ctx.sourceMethod,
        sourceToolOrResource: childCtx.sourceToolOrResource,
        mimeType,
        trust: ctx.trust
      });
    }

    for (const [key, child] of Object.entries(record)) {
      const childPath = `${path}.${key}`;
      const nextCtx = key === "text" || key === "content"
        ? childCtx
        : childCtx;
      if (typeof child === "string" && HUMAN_METADATA_KEYS.test(childPath)) {
        emitString(child, childPath, nextCtx, output, key === "uri" || key === "url" ? "url" : "metadata", mimeType);
      } else {
        visit(child, childPath, nextCtx, output);
      }
    }
  }
}

function emitString(
  value: string,
  path: string,
  ctx: ExtractionContext,
  output: ExtractedContent[],
  preferredKind?: ExtractedContentKind,
  mimeType?: string
): void {
  if (!value.trim()) {
    return;
  }

  const kind = preferredKind ?? inferKind(value, path);
  output.push({
    path,
    kind,
    text: kind === "binary" ? undefined : value,
    rawValue: kind === "binary" ? "[binary omitted]" : value,
    origin: ctx.origin,
    sourceServer: ctx.sourceServer,
    sourceMethod: ctx.sourceMethod,
    sourceToolOrResource: ctx.sourceToolOrResource,
    mimeType,
    trust: ctx.trust
  });

  if (kind !== "url") {
    for (const match of value.matchAll(URL_RE)) {
      output.push({
        path: `${path}<url:${match.index ?? 0}>`,
        kind: "url",
        text: match[0],
        rawValue: match[0],
        origin: ctx.origin,
        sourceServer: ctx.sourceServer,
        sourceMethod: ctx.sourceMethod,
        sourceToolOrResource: ctx.sourceToolOrResource,
        mimeType,
        trust: ctx.trust
      });
    }
  }
}

function inferKind(value: string, path: string): ExtractedContentKind {
  if (/(\.uri|\.url)$/iu.test(path) || /^https?:\/\//iu.test(value)) {
    return "url";
  }
  if (/(\.blob|\.data)$/iu.test(path) && BASE64ISH_RE.test(value)) {
    return "binary";
  }
  if (HUMAN_METADATA_KEYS.test(path)) {
    return "metadata";
  }
  return "text";
}

function firstString(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.length > 0);
}

function dedupe(contents: ExtractedContent[]): ExtractedContent[] {
  const seen = new Set<string>();
  const deduped: ExtractedContent[] = [];
  for (const content of contents) {
    const key = `${content.path}:${content.kind}:${content.text ?? ""}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(content);
    }
  }
  return deduped;
}
