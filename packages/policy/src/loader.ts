import { readFile } from "node:fs/promises";
import { parseYamlWithSchema } from "./errors.js";
import { policyDocumentSchema } from "./schema.js";
import type { PolicyDocument } from "./types.js";

export async function loadPolicyFile(path: string): Promise<PolicyDocument> {
  const raw = await readFile(path, "utf8");
  return parsePolicy(raw, path);
}

export function parsePolicy(raw: string, file = "policy"): PolicyDocument {
  return parseYamlWithSchema(policyDocumentSchema, raw, file);
}
