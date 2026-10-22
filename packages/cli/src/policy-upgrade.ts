import YAML, { isMap, isSeq, type Document, type Node, type YAMLSeq } from "yaml";

export interface PolicyUpgrade {
  /** Rule ids added from the shipped preset, in preset order. */
  added: string[];
  /** Rule ids present in both whose content differs; left as the user wrote them. */
  differs: string[];
  text: string;
}

function ruleId(node: unknown): string | undefined {
  if (!isMap(node)) return undefined;
  const id = node.get("id");
  return typeof id === "string" ? id : undefined;
}

function rulesOf(doc: Document, label: string): YAMLSeq {
  const rules = doc.get("rules", true);
  if (!isSeq(rules)) throw new Error(`${label} has no rules list.`);
  return rules;
}

/**
 * Adds the shipped preset's rules that a policy file is missing, each right after the nearest
 * earlier preset rule the file has (first match wins, so position matters). Rules the user
 * changed or added are kept as written, comments included.
 */
export function upgradePolicyText(current: string, preset: string): PolicyUpgrade {
  const doc = YAML.parseDocument(current);
  if (doc.errors.length > 0) throw new Error(`The policy file is not valid YAML: ${doc.errors[0]!.message}`);
  const shipped = YAML.parseDocument(preset);
  const rules = rulesOf(doc, "The policy file");
  const shippedRules = rulesOf(shipped, "The preset").items;
  const have = new Map<string, unknown>();
  for (const item of rules.items) {
    const id = ruleId(item);
    if (id) have.set(id, (item as Node).toJSON());
  }
  const added: string[] = [];
  const differs: string[] = [];
  let anchor: string | undefined;
  for (const item of shippedRules) {
    const id = ruleId(item);
    if (!id) continue;
    if (have.has(id)) {
      if (JSON.stringify(have.get(id)) !== JSON.stringify((item as Node).toJSON())) differs.push(id);
      anchor = id;
      continue;
    }
    const at = anchor === undefined ? 0 : rules.items.findIndex((candidate) => ruleId(candidate) === anchor) + 1;
    rules.items.splice(at, 0, (item as Node).clone());
    have.set(id, (item as Node).toJSON());
    added.push(id);
    anchor = id;
  }
  return { added, differs, text: added.length > 0 ? doc.toString() : current };
}
