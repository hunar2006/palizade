import { isMap, isScalar, LineCounter, parseDocument, type Document } from "yaml";
import type { z } from "zod";

export interface SchemaProblem {
  /** Dotted YAML path such as `servers.fs.sandbox.allowHosts`, or `(root)`. */
  path: string;
  line?: number | undefined;
  message: string;
  hint: string;
}

/** A YAML file that parsed but failed schema validation, with one entry per problem. Messages never include input values. */
export class SchemaValidationError extends Error {
  constructor(readonly file: string, readonly problems: SchemaProblem[]) {
    super(formatSchemaProblems(file, problems));
    this.name = "SchemaValidationError";
  }
}

const MAX_PROBLEMS = 20;

export function parseYamlWithSchema<S extends z.ZodType>(schema: S, raw: string, file: string): z.output<S> {
  const lineCounter = new LineCounter();
  const doc = parseDocument(raw, { lineCounter });
  if (doc.errors.length > 0) {
    const error = doc.errors[0]!;
    const line = error.linePos?.[0]?.line;
    throw new SchemaValidationError(file, [{ path: "(root)", line, message: `YAML syntax error: ${error.code}`, hint: "Fix the indentation or quoting on this line; YAML uses spaces, not tabs." }]);
  }
  const result = schema.safeParse(doc.toJS());
  if (result.success) return result.data;
  throw new SchemaValidationError(file, schemaProblems(schema, result.error.issues, doc, lineCounter));
}

export function schemaProblems(schema: z.ZodType, issues: readonly z.core.$ZodIssue[], doc?: Document, lineCounter?: LineCounter): SchemaProblem[] {
  return flattenIssues(issues).slice(0, MAX_PROBLEMS).map((issue) => {
    const path = issue.path.map(String);
    const keyPath = issue.code === "unrecognized_keys" && issue.keys.length > 0 ? [...path, issue.keys[0]!] : path;
    return {
      path: keyPath.length > 0 ? keyPath.join(".") : "(root)",
      line: doc && lineCounter ? lineOf(doc, lineCounter, keyPath) : undefined,
      message: issue.code === "unrecognized_keys" ? `Unknown key${issue.keys.length > 1 ? "s" : ""} ${issue.keys.map((key) => `'${key}'`).join(", ")}` : issue.message,
      hint: hintFor(schema, issue, path)
    };
  });
}

export function formatSchemaProblems(file: string, problems: SchemaProblem[]): string {
  const lines = [`Invalid ${file} (${problems.length} problem${problems.length === 1 ? "" : "s"}):`];
  for (const problem of problems) {
    lines.push(`  ${problem.path}${problem.line ? ` (line ${problem.line})` : ""}: ${problem.message}`);
    lines.push(`    fix: ${problem.hint}`);
  }
  return lines.join("\n");
}

function flattenIssues(issues: readonly z.core.$ZodIssue[]): z.core.$ZodIssue[] {
  return issues.flatMap((issue) => {
    if (issue.code !== "invalid_union" || issue.errors.length === 0) return [issue];
    // Report the branch that got furthest (most specific path); a plain wrong type stays a single issue.
    const best = [...issue.errors].sort((left, right) => depth(right) - depth(left))[0]!;
    if (depth(best) === 0) return [issue];
    return flattenIssues(best.map((nested) => ({ ...nested, path: [...issue.path, ...nested.path] })));
  });
}

function depth(issues: readonly z.core.$ZodIssue[]): number {
  return Math.max(0, ...issues.map((issue) => issue.path.length + (issue.code === "unrecognized_keys" ? 1 : 0)));
}

function hintFor(schema: z.ZodType, issue: z.core.$ZodIssue, path: string[]): string {
  switch (issue.code) {
    case "unrecognized_keys": {
      const known = knownKeysAt(schema, path);
      const suggestion = known.length > 0 ? closest(issue.keys[0]!, known) : undefined;
      if (suggestion) return `Did you mean '${suggestion}'? Otherwise remove the key.`;
      return known.length > 0 ? `Remove it. Allowed keys here: ${known.slice(0, 12).join(", ")}${known.length > 12 ? ", ..." : ""}.` : "Remove it or check its indentation.";
    }
    case "invalid_type":
      return /received undefined/u.test(issue.message) ? `Add '${path.at(-1) ?? "this value"}' (expected ${issue.expected}).` : `Use a ${issue.expected} here.`;
    case "invalid_value":
      return `Use one of: ${issue.values.map((value) => JSON.stringify(value)).join(", ")}.`;
    case "too_small":
      return issue.origin === "array" ? `List at least ${String(issue.minimum)} item(s).` : `Use a value of at least ${String(issue.minimum)}.`;
    case "too_big":
      return issue.origin === "array" ? `List at most ${String(issue.maximum)} item(s).` : `Use a value of at most ${String(issue.maximum)}.`;
    case "invalid_format":
      return `Use a value in ${issue.format === "regex" ? "the documented format" : `${issue.format} format`}.`;
    case "invalid_union":
      return "Use one of the documented forms for this setting.";
    default:
      return "Change this setting so it satisfies the message above.";
  }
}

/** Returns a function mapping a YAML path to its 1-based line, or undefined when the text is not valid YAML. */
export function createLineLocator(raw: string): (path: Array<string | number>) => number | undefined {
  const lineCounter = new LineCounter();
  const doc = parseDocument(raw, { lineCounter });
  return (path) => doc.errors.length > 0 ? undefined : lineOf(doc, lineCounter, path.map(String));
}

function lineOf(doc: Document, lineCounter: LineCounter, path: string[]): number | undefined {
  let node: unknown = doc.contents;
  let offset: number | undefined = rangeStart(node);
  for (const segment of path) {
    if (!isMap(node) && !(node && typeof node === "object" && "items" in node)) break;
    const items = (node as { items: unknown[] }).items;
    if (isMap(node)) {
      const pair = node.items.find((item) => isScalar(item.key) && String(item.key.value) === segment);
      if (!pair) break;
      offset = rangeStart(pair.key) ?? offset;
      node = pair.value;
    } else {
      const index = Number(segment);
      if (!Number.isInteger(index) || index >= items.length) break;
      node = items[index];
      offset = rangeStart(node) ?? offset;
    }
  }
  return offset === undefined ? undefined : lineCounter.linePos(offset).line;
}

function rangeStart(node: unknown): number | undefined {
  const range = (node as { range?: [number, number, number] } | null | undefined)?.range;
  return range?.[0];
}

type SchemaInternals = { _zod?: { def?: Record<string, unknown> & { type?: string } } };

/** Object keys accepted at a path, following optional/default/pipe wrappers, records, arrays and unions. */
export function knownKeysAt(schema: z.ZodType, path: string[]): string[] {
  let current: SchemaInternals[] = [schema as unknown as SchemaInternals];
  for (const segment of [...path, undefined]) {
    current = current.flatMap(unwrap);
    if (segment === undefined) break;
    current = current.flatMap((node) => {
      const def = node._zod?.def;
      if (def?.type === "object") {
        const child = (def.shape as Record<string, SchemaInternals>)[segment];
        return child ? [child] : [];
      }
      if (def?.type === "record") return [def.valueType as SchemaInternals];
      if (def?.type === "array") return [def.element as SchemaInternals];
      return [];
    });
  }
  return [...new Set(current.flatMap((node) => node._zod?.def?.type === "object" ? Object.keys(node._zod.def.shape as object) : []))];
}

function unwrap(node: SchemaInternals): SchemaInternals[] {
  const def = node._zod?.def;
  if (!def) return [];
  if (["optional", "nullable", "default", "prefault", "readonly", "catch", "nonoptional"].includes(def.type ?? "")) return unwrap(def.innerType as SchemaInternals);
  if (def.type === "pipe") return unwrap(def.in as SchemaInternals);
  if (def.type === "union") return (def.options as SchemaInternals[]).flatMap(unwrap);
  return [node];
}

function closest(input: string, candidates: string[]): string | undefined {
  let best: { key: string; distance: number } | undefined;
  for (const candidate of candidates) {
    const distance = editDistance(input.toLowerCase(), candidate.toLowerCase());
    if (!best || distance < best.distance) best = { key: candidate, distance };
  }
  return best && best.distance <= Math.max(2, Math.floor(input.length / 3)) ? best.key : undefined;
}

function editDistance(left: string, right: string): number {
  if (left.length > 64 || right.length > 64) return Number.POSITIVE_INFINITY;
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= right.length; j += 1) {
      current[j] = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + (left[i - 1] === right[j - 1] ? 0 : 1));
    }
    previous = current;
  }
  return previous[right.length]!;
}
