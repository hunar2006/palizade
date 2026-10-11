import { escapeNonPrinting, findHiddenUnicode } from "@palizade/detectors";
import { canonicalToolView, hashTool } from "./canonical.js";
import type { PalizadeLock } from "./lockfile.js";
import type { McpTool } from "./mcp.js";

export interface FieldDiff {
  path: string;
  before?: string | undefined;
  after?: string | undefined;
  /** First differing UTF-8 byte offset for changed string fields. */
  byteOffset?: number | undefined;
  beforeBytes?: number | undefined;
  afterBytes?: number | undefined;
  hiddenCodePoints?: string[] | undefined;
}

export interface ToolDiffEntry {
  tool: string;
  status: "added" | "removed" | "changed" | "unchanged";
  fields: FieldDiff[];
  note?: string | undefined;
}

export function diffToolsAgainstLock(lock: PalizadeLock, serverName: string, tools: McpTool[]): ToolDiffEntry[] {
  const locked = lock.servers[serverName]?.tools ?? {};
  const entries: ToolDiffEntry[] = [];
  const seen = new Set<string>();
  for (const tool of tools) {
    seen.add(tool.name);
    const existing = locked[tool.name];
    const current = flattenLeaves(canonicalToolView(tool));
    if (!existing) {
      entries.push({ tool: tool.name, status: "added", fields: [...current].map(([path, value]) => fieldFor(path, undefined, value)) });
      continue;
    }
    if (existing.hash === hashTool(tool)) {
      entries.push({ tool: tool.name, status: "unchanged", fields: [] });
      continue;
    }
    if (existing.snapshot === undefined) {
      entries.push({
        tool: tool.name,
        status: "changed",
        note: "hash changed; the lock entry has no stored snapshot (approved before v0.4), so every current field is shown",
        fields: [...current].map(([path, value]) => fieldFor(path, undefined, value))
      });
      continue;
    }
    const previous = flattenLeaves(existing.snapshot);
    const paths = [...new Set([...previous.keys(), ...current.keys()])].sort();
    entries.push({
      tool: tool.name,
      status: "changed",
      fields: paths
        .filter((path) => previous.get(path) !== current.get(path))
        .map((path) => fieldFor(path, previous.get(path), current.get(path)))
    });
  }
  for (const [name, entry] of Object.entries(locked)) {
    if (seen.has(name)) continue;
    const previous = entry.snapshot === undefined ? new Map<string, string>() : flattenLeaves(entry.snapshot);
    entries.push({ tool: name, status: "removed", fields: [...previous].map(([path, value]) => fieldFor(path, value, undefined)) });
  }
  return entries;
}

export function formatToolDiff(serverName: string, entries: ToolDiffEntry[]): string {
  const lines: string[] = [];
  const changed = entries.filter((entry) => entry.status !== "unchanged");
  if (changed.length === 0) {
    return `${serverName}: tool metadata matches the lockfile (${entries.length} tool(s)).`;
  }
  lines.push(`${serverName}: ${changed.length} tool(s) differ from the lockfile. Non printing characters are shown as \\u{XXXX}.`);
  for (const entry of changed) {
    lines.push("", `${entry.status.toUpperCase()} ${serverName}/${escapeNonPrinting(entry.tool)}`);
    if (entry.note) lines.push(`  note: ${entry.note}`);
    for (const field of entry.fields) {
      lines.push(`  ${escapeNonPrinting(field.path)}`);
      if (field.before !== undefined) lines.push(`    - ${escapeNonPrinting(field.before)}`);
      if (field.after !== undefined) lines.push(`    + ${escapeNonPrinting(field.after)}`);
      if (field.byteOffset !== undefined) {
        lines.push(`    bytes: ${field.beforeBytes} -> ${field.afterBytes}, first difference at byte ${field.byteOffset}`);
      }
      if (field.hiddenCodePoints && field.hiddenCodePoints.length > 0) {
        lines.push(`    WARNING hidden characters: ${field.hiddenCodePoints.join(", ")}`);
      }
    }
  }
  return lines.join("\n");
}

function fieldFor(path: string, before: string | undefined, after: string | undefined): FieldDiff {
  const field: FieldDiff = { path, before, after };
  if (before !== undefined && after !== undefined) {
    const a = Buffer.from(before, "utf8");
    const b = Buffer.from(after, "utf8");
    let offset = 0;
    while (offset < a.length && offset < b.length && a[offset] === b[offset]) offset += 1;
    field.byteOffset = offset;
    field.beforeBytes = a.length;
    field.afterBytes = b.length;
  }
  const hidden = findHiddenUnicode(`${path}\n${after ?? ""}`);
  if (hidden.count > 0) field.hiddenCodePoints = hidden.codePoints;
  return field;
}

function flattenLeaves(value: unknown): Map<string, string> {
  const leaves = new Map<string, string>();
  const visit = (node: unknown, path: string): void => {
    if (typeof node === "string") {
      leaves.set(path, node);
      return;
    }
    if (Array.isArray(node)) {
      if (node.length === 0) leaves.set(path, "[]");
      node.forEach((item, index) => visit(item, `${path}[${index}]`));
      return;
    }
    if (node && typeof node === "object") {
      const keys = Object.keys(node as Record<string, unknown>).sort();
      if (keys.length === 0) leaves.set(path, "{}");
      for (const key of keys) visit((node as Record<string, unknown>)[key], path ? `${path}.${key}` : key);
      return;
    }
    leaves.set(path, JSON.stringify(node));
  };
  visit(value, "");
  return leaves;
}
