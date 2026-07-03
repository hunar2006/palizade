import { readFile } from "node:fs/promises";
import YAML from "yaml";
import { policyDocumentSchema } from "./schema.js";
import type { PolicyDocument } from "./types.js";

export async function loadPolicyFile(path: string): Promise<PolicyDocument> {
  const raw = await readFile(path, "utf8");
  return parsePolicy(raw);
}

export function parsePolicy(raw: string): PolicyDocument {
  const data = YAML.parse(raw);
  return policyDocumentSchema.parse(data);
}
